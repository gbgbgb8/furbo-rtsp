# freeFurbo — agent field guide (sanitized)

Goal: owner's Furbo 2.5T (Ambarella S2L, board `S2LM_FURBO25`) streaming locally to
Home Assistant — no vendor cloud, LAN only. Unofficial; owner-authorized; reversible.
All device-specific values are placeholders: `<CAM_IP>`, `<HA_IP>`, `<RTSP_PASS>`,
`person.<you>`. The per-device RTSP password is never in this doc — you read it off
the camera in Phase D. Worked end-to-end Oct 2026 (HA 2026.10, HAOS 18).

## TL;DR end state

1. Web login: `admin`/`admin` with digest realm **`ycam.com`** (camera challenges with a different realm — this mismatch is the whole trick).
2. Root shell: CVE-2021-32452 command injection in `ldc.cgi` with that login.
3. Stock RTSP can **never** authenticate a remote client (3 library bugs). Patch 7 instructions in `/usr/lib/libamprotocol-rtsp.so.2.0.0` on disk + reboot → plain `rtsp://admin:<RTSP_PASS>@<CAM_IP>:554/stream0` works (1080p H.264 + AAC).
4. Video only flows while the encoder runs. Start/stop it with the camera's own tool: `/usr/bin/test_video_service_dyn_air_api --start|--stop`.
5. HA: go2rtc restreams the camera; `shell_command` calls a helper script that starts the encoder **and re-declares the go2rtc stream** (see "go2rtc latch", Phase I). Dashboard button runs it for 5 min.

## Dead ends — do not spend tokens on these

- **Digest brute-forcing after you have the correct password.** Remote RTSP auth is unreachable code; ~40 variants (realms, hash orders, no-qop, field order) all 401. If password is verified (Phase D) and RTSP still 401s, go straight to the patch.
- **Live-patching `/proc/<pid>/mem`.** Writes verify but the process executes stale I-cache on the hot loopback path. Patch the file, reboot.
- **Re-deriving the realm from the challenge.** Challenge says `ambarella`; the stored hash uses `ycam.com`. Just use `ycam.com`.
- **Treating CGI HTTP 500 / client timeouts as "command failed."** They usually executed. Verify side effects, never status codes.
- **Restarting `rtsp_svc` by hand.** It ignores SIGTERM; SIGKILL leaves a defunct PID + stale `/tmp/rtsp_svc.pid`, and the watchdog reboots the camera anyway. Just `reboot`.
- **Single-`src` go2rtc PUT** to "fix" a stream: it replaces all sources and wipes the primary. Always PUT every source, and URL-encode `#` as `%23`.

## Working on the camera (read before sending any command)

The `ldc.cgi` shell is fragile. Rules that prevent most failures:

- Commands reach `sh` **twice**; quotes don't protect the second pass. No `|` inside quoted patterns — one simple grep pattern per command.
- **~120 char limit** per injected command; longer is silently truncated. One or two short statements per request.
- Expect `unknown option found: 63` noise (harmless) and the echoed `test_ldc` line in every response.
- Output truncates at ~1–2 KB. Print little: `grep -c`, `od` at computed offsets, redirect to a file and read it back in chunks. Busybox `grep -abo` is broken (silently empty).
- Pace requests 2–3 s apart. Floods (or killing services) trip a watchdog reboot (~50–60 s recovery; it comes back by itself, patch persists). lighttpd on :80 jams under load; :443 works then but its TLS handshake also times out under load. Wait, don't hammer.
- HTTP 500 from CGI often still executed your command. Timeouts too. Check the file/bytes you expected to change before re-sending.

## Phase A — recon

| Port | Expect |
|---|---|
| 80, 443 | lighttpd/1.4.40, 401 digest realm `ambarella` (443 cert is the expired Ambarella SDK sample — not a password) |
| 554 | RTSP, 401 on DESCRIBE, digest realm `chicony.com`; `OPTIONS` → 200 |
| 8080 | closed |

## Phase B — web login

Send digest auth as `admin`/`admin` but with `realm="ycam.com"` and
`HA1 = MD5("admin:ycam.com:admin")` = `913fd17138fb6298ccf77d3853ddcf9f` (factory
value, published by Somerset Recon 2021). Compute nonce/uri/qop normally from
the challenge. Gate: HTTP 200. (`/cgi-bin/get_vin.cgi` then reports 1920x1080.)

## Phase C — root shell (CVE-2021-32452)

`GET /cgi-bin/ldc.cgi?mode=;<url-encoded command>;` with the Phase-B Authorization
header. The CGI runs your command as root via `system()`. Wrap it in a helper:
first request unauthenticated to harvest the nonce, then the authorized request
(reference implementation any agent can rewrite in ~40 lines of stdlib HTTP +
`hashlib.md5`). Gate: `id` → `uid=0(root)`.

## Phase D — read the RTSP password

```sh
cat /etc/Account.txt                    # admin:0:<RTSP_PASS>
od -c /dev/adc/furbo2_rtsp.password     # exactly the password, no newline
od -c /etc/webpass.txt                  # admin:chicony.com:<32-hex>
```

Gate: all three agree, i.e. `MD5("admin:chicony.com:<RTSP_PASS>")` equals the
hash in `webpass.txt`. RTSP user is `admin`, realm `chicony.com`. Per-device; no
universal value exists. **RTSP will still 401 now. That is expected.**

Useful facts: RTSP config `/etc/oryx/apps/rtsp_server.acs` → user db
`/etc/webpass.txt`, `need_auth=true`, `max_client_num=5` (space RTSP attempts
out; saturation looks like a dead camera). One process `rtsp_svc` owns :554.
Paths `/stream0`–`/stream3`, `/stream` exist; `/` is 404.

## Phase E — why the correct password 401s (background, brief)

In `libamprotocol-rtsp.so.2.0.0` (stripped Thumb ELF; disassemble with capstone
`CS_MODE_THUMB` — binutils objdump defaults to ARM and outputs garbage):

1. Both request handlers gate on `strncmp(client_ip, "127.0.0.1", 9)` → remote clients 401 before auth is parsed (file offsets 0x43d2, 0x44ba, 0x474e, 0x4830).
2. `parse_authentication_header` (0x38f4) is dead code; auth fields stay NULL and pre-checks fail even on loopback (checks at 0x4544 / 0x4842).
3. `authenticate` (0x81f8) hashes components in swapped order, and the db loader's `fscanf` would swallow a trailing newline into the stored hash anyway.

To inspect: copy the library into the web root (`/webSvr/web/`), download via the
Phase-B login, delete the copy. Original file md5: `ecd72214e238f4635c8894f078177f35`.

## Phase F — the patch (file on disk, then reboot)

Back up first: `cp /usr/lib/libamprotocol-rtsp.so.2.0.0 /usr/lib/rtsp-lib-backup.bin`.
Write each row with `dd conv=notrunc` at the decimal offset, **one dd per CGI
command**, read back and byte-compare each before continuing:

| Offset hex (dec) | Original | Patched | Effect |
|---|---|---|---|
| 0x81f8 (33272) | `2d e9 f0 4f` | `01 20 70 47` | `authenticate` returns 1 |
| 0x4544 (17732) | `f8 d0 90 15` | `47 e0` | handler 1 skips NULL-field checks |
| 0x4842 (18498) | `f8 d0 90 15` | `45 e0` | handler 2 same |
| 0x43d2 (17362) | `blx strncmp` | `00 20 00 bf` | loopback gate always matches |
| 0x44ba (17594) | `blx strncmp` | `00 20 00 bf` | gate tail, handler 1 |
| 0x474e (18254) | `blx strncmp` | `00 20 00 bf` | gate, handler 2 |
| 0x4830 (18480) | `blx strncmp` | `00 20 00 bf` | gate tail, handler 2 |

**Costliest trap:** `movs r0,#0` = bytes `00 20`. `01 20` is `movs r0,#1` — patch
verifies byte-wise yet gates reject everyone and you get 401 again. If patched +
rebooted + still 401, suspect exactly this byte.

Then `reboot` via injection (request times out as it drops — fine). Back in ~60 s.

## Phase G — verify RTSP

```sh
ffprobe -v error -rtsp_transport tcp -show_entries stream=codec_name,width,height \
  rtsp://admin:<RTSP_PASS>@<CAM_IP>:554/stream0
```

Gate: SDP lists `h264` + `aac`. **Audio always flows; video only while the
encoder runs** (next phase). Audio-only at this point is normal, not a failure.

## Phase H — encoder on demand

Camera's own SDK tool: `timeout -s KILL 10 /usr/bin/test_video_service_dyn_air_api --start|--stop`
(`--show-stream-status` prints `Stream[n]: encoding` or `No stream in encoding!`;
`--show-lock-state`, `--show-working-mode` also useful).

- After a **camera reboot**, a bare `--start` can return 0 yet be silently ignored
  until the encoder has been stopped once. Always **stop → wait ~2 s → start**. Bake this into any wrapper.
- Spin-up is usually ~10–25 s but can take **60–100 s** (notably after a stop or a recovery); the web UI gets sluggish meanwhile. Black video inside the first ~90 s is not a failure — wait, then Phase-G ffprobe / one frame grab.
- **One start attempt, then hands off.** Overlapping start/stop cycles and RTSP probing during spin-up repeatedly tripped watchdog reboots in our testing (~50 s recovery each, and each reboot restarts the clock). If it hasn't flowed by ~90 s, stop once, wait, start once.
- Encoder runs warm — don't leave it on 24/7; HA turns it off (Phase I).
- If RTSP starts **resetting connections on DESCRIBE** after heavy probing, `rtsp_svc` is wedged; don't poke it — `reboot` and wait.
- The SDK client can block on its IPC socket **ignoring SIGTERM**; a plain `timeout 8` wrapper then leaves a spinning process on the camera. Always wrap as `timeout -s KILL 10`.
- **Wedged frame pipeline** (signature: load average climbing past ~5, `tfp2pd.log` repeating `Hasn't got any frame in 120 secs. Restart all services`, `cec_snapshot rc=-1` in `dmesg`, `--start` returning 0 but ignored, status clients hanging): warm `reboot` may NOT clear it — the image-sensor/IAV block needs a **full power drain: unplug 60 s**, replug, then hands-off ~5 min (log-only checks) before one start attempt. Verify recovery by load settling near 1 and the restart loop gone, not just by ping.
- Ground-truth split when stuck: if the owner's **Furbo app live view also fails**, the camera's pipeline is sick (power drain / vendor reset territory). If the app works, the hardware path is fine and only the local trigger sequence is wrong.

## Phase I — Home Assistant

Architecture: HA → go2rtc (one RTSP client to camera) → `camera.furbo`;
`shell_command.furbo_start/stop` → helper script on HA host → CGI (Phase C) →
encoder tool (Phase H). Video H.264 copy; second go2rtc source
`ffmpeg:furbo#audio=opus` for browser/WebRTC audio.

Files on HA host: `/config/scripts/ldc_inject.py`, `/config/scripts/furbo_stream.py`
(start/stop/probe, stdlib only), `/config/scripts/.furbo_rtsp_pass` (password only).
go2rtc stream (in HA's go2rtc config or package; keep the URL in `secrets.yaml`):

```yaml
go2rtc:
  streams:
    furbo:
      - ffmpeg:rtsp://admin:<RTSP_PASS>@<CAM_IP>:554/stream0#video=copy#audio=copy
      - ffmpeg:furbo#audio=opus
shell_command:
  furbo_start: python3 /config/scripts/furbo_stream.py start
  furbo_stop: python3 /config/scripts/furbo_stream.py stop
```

`camera.furbo` is auto-created by the go2rtc integration. Script
`furbo_live_5min` (mode: restart): `furbo_start` → delay 5 min → `furbo_stop`;
dashboard = picture-entity card + button calling that script (optional iframe
`http://<HA_IP>:1984/webrtc.html?src=furbo`). Automations: person home → start;
away 5 min → stop; 23:00 → stop. YAML changes to go2rtc/shell_command need an
HA restart. Automations can't live in an HA package if config uses
`automation: !include` — append them to `automations.yaml`; scripts can be
UI/storage or YAML.

**go2rtc latch (the bug that eats an afternoon):** go2rtc negotiates its producer
RTSP session once. If it connects while the encoder is idle, the session is
audio-only and can *never* gain video — `camera.furbo` stays `unavailable` after
you press start even though the camera streams fine to ffprobe. Fix: after the
encoder is up (~8 s), re-declare the stream with all sources:
`PUT http://<HA_IP>:1984/api/streams?name=furbo&src=ffmpeg:<url>%23video=copy%23audio=copy&src=ffmpeg:furbo%23audio=opus`
(from the HA host, `127.0.0.1:1984` works). Do this **inside** the start helper so
every caller (button, presence, manual) gets it. Best-effort: unreachable API must
not fail the start. Verify at the go2rtc layer first (`GET /api/frame.jpeg?src=furbo`
→ 1920×1080 JPEG), not producer state — producers are demand-driven and report
nothing while nobody watches.

**HA tile lag is normal:** after an encoder (re)start, HA's own camera path
(`camera_proxy` snapshots, picture-entity live view) can keep failing (HTTP 500)
for a few minutes *after* go2rtc already serves frames — HA's stream worker
renegotiates on its own schedule and recovers by itself. A 500 snapshot is not
proof the stream is down; check go2rtc `frame.jpeg` before touching anything,
and don't chase HA go2rtc reload endpoints (they errored and weren't needed).

**Set user expectations on the dashboard card:** real spin-up timing (~90 s,
black at first), WebRTC iframe as the primary live view (it comes up before the
HA tile), and "don't re-tap while waiting" — with `mode: restart` scripts and a
stop-first start helper, every extra tap stops the encoder and restarts the
spin-up clock, which can make a working setup look permanently broken.

HA access pattern (for agents): long-lived token from the user's secret store
(OS keychain etc.) — **never print it**. REST `/api/states`,
`/api/services/...?return_response=true` (shell_command returns stdout — gold for
debugging). Add-on files: temporarily map the Terminal & SSH add-on port via the
Supervisor API (`supervisor/api` WS command), edit, then unmap and verify closed.
Backup every HA file before editing (`*.bak-<date>`).

## Pitfalls index

| Symptom | Cause | Action |
|---|---|---|
| RTSP 401, password verified | stock library (Phase E) | patch (Phase F); check `00 20` bytes |
| Patch read-back OK, still 401 | `01 20` vs `00 20` inversion | fix bytes, reboot |
| `/proc/mem` patch verified, no effect | stale I-cache | patch file + reboot instead |
| SDP ok, audio only | encoder idle | start encoder (Phase H) |
| Encoder "encoding" but no video packets | post-reboot start ignored | stop → start cycle |
| RTSP resets on DESCRIBE | wedged `rtsp_svc` after floods | reboot camera, wait 60 s |
| CGI timeouts / HTTP 500 | load, output-stage failure | assume executed; verify side effect; pace |
| HA snapshot works, live card black | go2rtc audio-only latch | stream re-declare in start path |
| Stream lost primary source after API PUT | single-src PUT / raw `#` | PUT all sources, `%23` |
| Intermittent "camera died" under probing | 5-client RTSP saturation / watchdog | one consumer via go2rtc; wait |
| `python3` missing in SSH add-on shell | add-on ≠ HA core env | shell_command still fine; test via service |
| Camera reboots mid-testing | watchdog under sustained load | normal; wait ~60 s, patch persists |
| `--start` rc=0 but no video; load climbs; `Restart all services` in `tfp2pd.log` | wedged frame pipeline (often after a hard power-cut) | unplug 60 s (not a warm reboot), hands-off 5 min, retry once |
| Start/stop cycles seem to reboot the camera | thrash during encoder spin-up + probing load | one start attempt, hands off ~90 s |
| HA snapshot 500, but go2rtc `frame.jpeg` works | HA stream worker not yet renegotiated | wait a few minutes; use WebRTC view; HA recovers alone |
| Button "never works" when re-tapped | `mode: restart` + stop-first start resets spin-up per tap | tap once, wait the full ~90 s |

## Revert

Camera: `cp /usr/lib/rtsp-lib-backup.bin /usr/lib/libamprotocol-rtsp.so.2.0.0 && reboot`
(stock behavior: all remote RTSP 401). While patched, the RTSP server accepts any
credentials — keep the camera on a firewalled IoT VLAN, never port-forward it.
HA: remove package/automations/scripts/secret.

## Sources

- Somerset Recon, *Hacking the Furbo Dog Camera: Part II* (2021) — factory account, realm quirk, CVE-2021-32452: https://www.somersetrecon.com/blog/2021/hacking-the-furbo-dog-camera-part-ii
- PoC: https://github.com/Somerset-Recon/furbo-research (`command-injection/furbo_ldc_cmd_inj.py`)
- CVE-2020-24918 (RTSP parser overflow) exists in the same library; not needed here.
