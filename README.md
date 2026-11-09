# Photo Drop

A photo drop server that runs on your Android phone and turns it into a
private, shareable upload inbox. A friend opens a secret link in any phone
browser, picks photos and videos, watches them upload with real progress, and
lands on a confirmation page. Files land in `DCIM/PhotoDrop` on your phone,
so **Google Photos backs them up to your account automatically**.

Nothing is installed on the friend's phone. Nothing is stored on anyone else's
server. No app store, no account, no subscription.

```
friend's browser  ──HTTPS──▶  Cloudflare Tunnel  ──▶  Termux  ──▶  DCIM/PhotoDrop
  (nothing installed)         (public link)         (this repo)       │
                                                              Google Photos
                                                              backs it up
```

> **Set it up in 10 minutes.** The fastest path needs no APK build and no
> computer: install Termux on the phone, copy this repo in, run one command.

## Requirements

- Any Android phone (Android 8+ works; tested on modern Samsung)
- [Termux](https://f-droid.org/packages/com.termux/) **and** [Termux:API](https://f-droid.org/packages/com.termux.api/) installed **from the same source** (both F-Droid, or both Play Store). A signature mismatch makes `termux-media-scan` hang — this is the #1 setup bug.
- A friend with any phone browser

## Fastest setup — no computer, no APK

1. Install **Termux** + **Termux:API** (same source!) on the phone. Open Termux once.
2. Copy this repo onto the phone. Easiest: Download ZIP from the
   [latest release](https://github.com/kumar-karan/photo-drop/releases) and
   unzip to `~/photo-drop/`, or:
   ```bash
   pkg install git
   git clone https://github.com/kumar-karan/photo-drop.git ~/photo-drop
   ```
3. Run the one-time install:
   ```bash
   cd ~/photo-drop
   bash install.sh
   ```
   It installs Python + `cloudflared`, grants storage, generates tokens,
   creates `DCIM/PhotoDrop`, and probes which media-scan techniques your phone
   supports. Safe to re-run.
4. Set battery to Unrestricted (once):
   **Settings → Apps → Termux → Battery → Unrestricted**
5. Start it:
   ```bash
   bash start.sh --tunnel
   ```
   It prints a link like:
   ```
   https://<something>.trycloudflare.com/d/<token>
   ```
   **Send that link to your friend.** That link *is* the password — anyone
   with it can upload while it is running.
6. One-time Google Photos step (you only do this once):
   Google Photos → profile → **Backup** → ON →
   **Backup folders → DCIM → PhotoDrop** → ON.

Keep the phone plugged in while it runs. Stop with `bash stop.sh`.

## Recommended — launcher app (one-tap Start / Stop)

The app (`dev.photodrop.app`) does the same thing with a button and always
shows the live link + QR code. Build it on any Mac/Linux/Windows machine:

```bash
git clone https://github.com/kumar-karan/photo-drop.git
cd photo-drop
bash android/build.sh        # must print BUILD_OK (bootstraps SDK automatically)
bash deploy.sh               # pushes server + app to a USB-connected phone
```

Then install `android/photodrop.apk` on the phone (tap it, or
`adb install android/photodrop.apk`), open **Photo Drop → Start**, and share
the link it shows. **Stop** shuts the server and tunnel down cleanly —
including when you swipe the app away.

> **No SDK installed?** `build.sh` downloads the official Android
> command-line tools into `./android-sdk/` (git-ignored, ~461 MB) and
> installs platform 34 for you. Or grab a prebuilt APK from
> [Releases](https://github.com/kumar-karan/photo-drop/releases).

On your own Wi-Fi only (no internet, no tunnel): `bash start.sh` and use the
local URL it prints.

## Live owner dashboard

There are two ways to watch the drop, and both show the same live state:

- **In the app (recommended).** With the server running, tap **Open live dashboard**
  on the Photo Drop main screen. It opens the dashboard inside the app over loopback
  (`127.0.0.1`), independent of the tunnel.
- **In any browser.** Open `<base-url>/owner/<owner-token>`, for example
  `http://127.0.0.1:8080/owner/<owner-token>` on the phone itself. The owner
  token lives in `~/.photo-drop/env` (not the drop link's token).

The dashboard refreshes live and shows:
- Storage free/used with the 2 GiB reserve indicator;
- Real guest sessions with device labels (derived from User-Agent), IPs, short IDs, and states;
- Per-file progress bars, percentage, bytes written, and transfer speed in real time;
- Files received per session and recent uploads;
- Share link, uptime, and a one-tap **Clear temp cache** action.

### Live endpoints

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /owner/<owner-token>` | owner token | The dashboard page |
| `GET /owner/<owner-token>/api/state` | owner token | Full JSON snapshot polled by the dashboard |
| `GET /owner/<owner-token>/api/diagnostics` | owner token | Storage, process, tunnel and scan information |
| `POST /owner/<owner-token>/api/clear-parts` | owner token | Delete stale `.part` files |
| `GET /d/<drop-token>/status?batch=<id>` | drop token | Guest-facing free space, session file count and in-flight files |
| `GET /healthz` | none / token | Bare `{"ok": true}`; with `X-PD-Token` returns version, uptime, sessions, storage |

## What the friend sees

1. Opens your link. Nothing to install, no login.
2. Taps the drop zone, picks any number of photos/videos (HEIC, JPEG, MP4, MOV, Live Photos).
3. Each file uploads with a real percentage — from the browser's native
   `XMLHttpRequest` progress events, so it is bytes actually sent.
4. Sees the phone's free space before and during the session. Uploads pause
   below a 2 GiB safety reserve.
5. Lands on a confirmation page with a thumbnail grid and file list.

## Security model — please read

- **The link is the password.** Share it directly, hit Stop when done.
  Quick-tunnel links (`*.trycloudflare.com`) die on reboot/Stop and are
  re-minted on the next Start — an old link will not come back.
- **Tokens never travel in query strings.** Path-only, exchanged for an
  `HttpOnly`, `SameSite=Lax` cookie. Query strings leak into logs/`Referer`.
- **`/healthz` reveals nothing** without a token.
- **Server binds `127.0.0.1`**; `cloudflared` terminates TLS in front of it.
  Never set `PHOTO_DROP_HOST=0.0.0.0` unless you intend LAN exposure.
- **Space is checked twice** (before + during write). Rejected uploads write
  nothing — bodies stream to `.part` files deleted on failure.

## Configuration

`~/.photo-drop/env`:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PHOTO_DROP_TOKEN` | generated | Drop link credential |
| `PHOTO_DROP_OWNER_TOKEN` | generated | Owner dashboard credential (`/owner/<token>`) |
| `PHOTO_DROP_DIR` | `/storage/emulated/0/DCIM/PhotoDrop` | Where files land (keep flat — nested folders confuse Google Photos) |
| `PHOTO_DROP_PORT` | `8080` | Local port |
| `PHOTO_DROP_HOST` | `127.0.0.1` | Bind address — keep local, tunnel fronts it |
| `PHOTO_DROP_RESERVE_BYTES` | `2147483648` (2 GiB) | Uploads stop below this free |
| `PHOTO_DROP_MAX_FILE_BYTES` | `2147483648` (2 GiB) | Per-file cap |
| `PHOTO_DROP_MAX_FILES` | `500` | Per-session cap |
| `PHOTO_DROP_MAX_CONCURRENT` | `3` | Uploads in flight; extras get 503 |

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Link returns HTTP 530 | Tunnel has no origin — server stopped. Start again; you get a *new* link. |
| `termux-media-scan` hangs | Termux + Termux:API from different sources. Reinstall both from the same source. |
| Photos don't appear in Google Photos | Enable the `PhotoDrop` backup folder, open Gallery once, reboot. Check owner dashboard scan report. |
| Upload stalls at 0% | Phone dozed. Plug in, Termux battery Unrestricted, retry. |
| `cloudflared` missing | `pkg install cloudflared` (must be Termux's build — upstream glibc binary won't run on Termux's bionic). |
| New server won't come up, or `Stop` doesn't actually stop it | Old builds relied on Termux `pkill`, which silently misses `setsid`'d Python processes (stale server keeps `:8080`). Pull the latest `start.sh`/`stop.sh`/`pd-control.sh`; they scan `/proc` and `TERM`→grace→`SIGKILL` any survivors before starting. |

## Planned improvements

1. **Stable tunnel URL** — named Cloudflare tunnel so the link survives reboots.
2. **Resumable chunked uploads** — save large video uploads on flaky networks.
3. **Token rotation + expiry** — rotate link from the owner dashboard.
4. **LAN-only mode** — PIN-protected local link for trusted Wi-Fi.

## Why not croc / Swap / Syncthing?

- **croc** — great, but no space pre-check and no MediaStore notification.
- **Swap** — LAN-only plain HTTP, no space check.
- **Syncthing-Fork** — only off-the-shelf MediaStore option, but heavy.
- Related: [croc](https://github.com/schollz/croc), [LocalSend](https://github.com/localsend/localsend), [Magic Wormhole](https://github.com/warner/magic-wormhole).

## Tests

```bash
pip install flask pytest
python3 -m pytest tests/ -q
```

Covers auth, upload, filename sanitisation, space guard, size guard, confirmation page, live session tracking and the owner state API (37 tests).

## License

MIT — see `LICENSE`.
