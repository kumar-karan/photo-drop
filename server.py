#!/data/data/com.termux/files/usr/bin/python
"""
Photo Drop — a single-file photo drop server for Android (Termux).

A friend opens a secret link in any phone browser, picks photos and videos,
watches them upload with real progress, and lands with a confirmation page.
The files land in DCIM on the owner's Samsung, which makes Google Photos
back them up to the owner's account automatically.

Everything the friend needs is a browser. Nothing is installed on their phone.

Design notes
------------
* MediaStore, not the filesystem, is the source of truth for Google Photos.
  Every completed file goes through media_scan.sh, which escalates through
  the known notification techniques and reports which one worked.
* Storage is checked *before* accepting a file and *during* the write, so a
  full disk degrades into a clean error instead of a half-written file.
* One file per request from the browser. That is what makes native XHR
  upload progress possible — the browser reports bytes-sent for free, which
  means no chunked protocol, no SSE, no websocket.
* Metadata lives in Termux home, never inside DCIM, so we never pollute the
  gallery with stray files.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from markupsafe import escape

from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    redirect,
    request,
    send_file,
)
from werkzeug.exceptions import ClientDisconnected
from werkzeug.utils import secure_filename

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

HOME = Path(os.environ.get("PHOTO_DROP_HOME", Path.home() / ".photo-drop"))
EXPORT = Path(os.environ.get("PHOTO_DROP_EXPORT", "/sdcard/Android/data/dev.photodrop.app/files"))

TOKEN = os.environ.get("PHOTO_DROP_TOKEN", "").strip()
OWNER_TOKEN = os.environ.get("PHOTO_DROP_OWNER_TOKEN", "").strip()

DEST = Path(os.environ.get("PHOTO_DROP_DIR", "/storage/emulated/0/DCIM/PhotoDrop"))

# One folder, deliberately.
#
# A dated layout such as DCIM/PhotoDrop/2026-10-16 reads better on the
# filesystem, but Google Photos lists nested folders separately. A parent that
# is switched on while its date subfolder is switched off backs up nothing at
# all, and it fails silently. One folder is one toggle with no way to half
# configure it, so there is no dated option to switch on by mistake.

HOST = os.environ.get("PHOTO_DROP_HOST", "127.0.0.1")
PORT = int(os.environ.get("PHOTO_DROP_PORT", "8080"))

# Free space we refuse to go below. Uploads stop cleanly rather than filling
# the device and wedging the phone.
RESERVE_BYTES = int(os.environ.get("PHOTO_DROP_RESERVE_BYTES", str(2 * 1024**3)))  # 2 GiB

MAX_FILE_BYTES = int(os.environ.get("PHOTO_DROP_MAX_FILE_BYTES", str(2 * 1024**3)))  # 2 GiB
MAX_FILES_PER_SESSION = int(os.environ.get("PHOTO_DROP_MAX_FILES", "500"))

# Concurrent uploads allowed at once. Flask's dev server spawns a thread per
# request, so without this a client could open hundreds of simultaneous
# multi-gigabyte writes and exhaust RAM, file descriptors or the disk write
# queue. Uploads are refused with 503 rather than queued, so a phone never
# silently builds a backlog it cannot drain.
MAX_CONCURRENT_UPLOADS = int(os.environ.get("PHOTO_DROP_MAX_CONCURRENT", "3"))
_UPLOAD_SLOTS = threading.BoundedSemaphore(max(1, MAX_CONCURRENT_UPLOADS))

_ACTIVE_LOCK = threading.Lock()
_ACTIVE_TRANSFERS = {}
_RECENT_UPLOADS = []


def get_active_upload_stats():
    with _ACTIVE_LOCK:
        now = time.time()
        # Prune recent records older than 45s
        _RECENT_UPLOADS[:] = [u for u in _RECENT_UPLOADS if (now - u["finished"]) < 45]

        in_flight = list(_ACTIVE_TRANSFERS.values())
        recent = list(_RECENT_UPLOADS)

        active_sids = {u["sid"] for u in in_flight}
        recent_sids = {u["sid"] for u in recent if (now - u["finished"]) < 30}
        all_sids = active_sids | recent_sids

        uploaders = len(all_sids)
        is_uploading = len(in_flight) > 0
        is_active = is_uploading or len(recent) > 0
        if uploaders == 0 and is_active:
            uploaders = 1

        in_flight_names = [u["name"] for u in in_flight]
        recent_names = [u["name"] for u in recent if u["name"] not in in_flight_names]

        return {
            "uploading": is_uploading,
            "active": is_active,
            "uploaders": uploaders,
            "in_flight_count": len(in_flight),
            "in_flight_files": in_flight_names,
            "recent_count": len(recent),
            "recent_files": recent_names,
        }

# How long a session cookie stays valid.
SESSION_TTL = int(os.environ.get("PHOTO_DROP_SESSION_TTL", str(12 * 3600)))

COOKIE = "pd_session"
MEDIA_SCAN = str(Path(__file__).with_name("media_scan.sh"))

BATCHES = HOME / "batches"
LOGS = HOME / "logs"

app = Flask(__name__)


# --------------------------------------------------------------------------
# storage & network helpers
# --------------------------------------------------------------------------


def disk_free() -> int:
    """Free bytes on the volume holding DEST.

    On Termux this is a FUSE view of shared storage; statvfs works through it.
    If it ever fails we report a large number rather than blocking uploads,
    because a wrong "disk full" is worse than no check at all.
    """
    probe = DEST if DEST.exists() else DEST.parent
    try:
        return shutil.disk_usage(probe).free
    except OSError:
        return RESERVE_BYTES * 100


def disk_total() -> int:
    """Total bytes on the volume holding DEST, for a used/free ratio."""
    probe = DEST if DEST.exists() else DEST.parent
    try:
        return shutil.disk_usage(probe).total
    except OSError:
        return 0


def disk_free_home() -> int:
    """Free bytes on the volume holding manifests, logs and the session store.

    Those live in Termux home, not in DEST, so a single check on DEST would
    miss a full home partition entirely.
    """
    try:
        return shutil.disk_usage(HOME).free
    except OSError:
        return RESERVE_BYTES * 100


def enough_space(needed: int) -> bool:
    return disk_free() - needed >= RESERVE_BYTES


def get_lan_ip() -> str:
    """Returns the primary LAN IPv4 address (e.g. 10.71.107.27)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_public_url() -> str:
    """Reads the current public tunnel URL if active."""
    for candidate in [
        HOME / "url",
        Path.home() / ".photo-drop" / "url",
        EXPORT / "public-url.txt",
    ]:
        if candidate.exists():
            try:
                val = candidate.read_text().strip()
                if val.startswith("http"):
                    return val
            except OSError:
                pass
    for log_path in [
        HOME / "logs" / "cloudflared.log",
        Path.home() / ".photo-drop" / "logs" / "cloudflared.log",
    ]:
        if log_path.exists():
            try:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    log_text = f.read()
                matches = re.findall(r"https://[a-z0-9-]+\.trycloudflare\.com", log_text)
                if matches:
                    return matches[-1]
            except Exception:
                pass
    return ""


def unique_name(raw: str, folder: Path) -> str:
    """Sanitise the uploaded filename and keep it recognisable.

    The name the friend saw on their own camera roll is what they will look
    for, and it is what shows up in Google Photos, so it is preserved. The
    random prefix this used to add made every file unreadable in a gallery for
    no gain: the folder is not browsable without the token anyway. Collisions
    get a numeric suffix instead.
    """
    base = secure_filename(raw or "photo")
    if not base or base in {".", ".."}:
        base = "photo"
    # secure_filename strips dots entirely, which costs us the extension.
    stem, dot, ext = raw.rpartition(".")
    if dot and len(ext) <= 5 and stem:
        base = f"{secure_filename(stem)}.{secure_filename(ext).lower()}"
    if len(base) > 120:
        stem, _, ext = base.rpartition(".")
        base = f"{stem[:100]}.{ext}" if ext else stem[:120]

    candidate = base
    n = 2
    while (folder / candidate).exists():
        stem, _, ext = base.rpartition(".")
        candidate = f"{stem}-{n}.{ext}" if ext else f"{base}-{n}"
        n += 1
    return candidate


def session_id() -> str:
    return request.cookies.get(COOKIE, "")


def new_session() -> str:
    return secrets.token_urlsafe(24)


def set_session_cookie(resp, sid: str):
    # Behind cloudflared the request reaching Flask is plain HTTP even though
    # the browser used HTTPS, so request.is_secure is False and Secure would
    # silently be dropped. Trust the proxy header instead.
    forwarded = request.headers.get("X-Forwarded-Proto", "")
    is_https = request.is_secure or forwarded.split(",")[0].strip() == "https"
    resp.set_cookie(
        COOKIE,
        sid,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="Lax",
        secure=is_https,
        path="/",
    )


def log(line: str):
    LOGS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    path = LOGS / "photo-drop.log"
    # Same reasoning as the manifest cap: rotate rather than grow forever.
    if path.exists() and path.stat().st_size > 2_000_000:
        path.replace(LOGS / "photo-drop.log.1")
    with open(path, "a") as fh:
        fh.write(f"{stamp} {line}\n")


# --------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------

TOKEN_OK = bool(TOKEN) and len(TOKEN) >= 12
if not TOKEN_OK:
    print(
        "\n  PHOTO_DROP_TOKEN is missing or shorter than 12 characters.\n"
        "  Refusing to start. Generate one with:\n"
        '      python -c "import secrets;print(secrets.token_urlsafe(16))"\n',
        file=__import__("sys").stderr,
    )
    raise SystemExit(1)

OWNER_OK = bool(OWNER_TOKEN) and len(OWNER_TOKEN) >= 12


def check_token(candidate: str, expected: str) -> bool:
    return hmac.compare_digest(candidate or "", expected or "")


# --- session store ---------------------------------------------------------
# The session cookie has to be validated against something. Comparing it to
# the master token can never succeed, because the cookie holds a random id.
# So sessions are recorded server-side and looked up here.
#
# This also gives batches a real owner: a batch id is only accepted if it was
# created by the session presenting it, which is what makes MAX_FILES_PER_SESSION
# mean anything.

SESSIONS = HOME / "sessions.json"
SESSION_LOCK = threading.Lock()

# Upper bound on the store so a long-running phone can't grow it forever.
MAX_SESSIONS = 200


def _load_sessions() -> dict:
    if not SESSIONS.exists():
        return {}
    try:
        return json.loads(SESSIONS.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_sessions(data: dict):
    # Atomic write so an ungraceful shutdown cannot leave a half-written JSON.
    tmp = SESSIONS.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(SESSIONS)


def session_valid(sid: str) -> bool:
    if not sid or len(sid) < 16:
        return False
    with SESSION_LOCK:
        s = _load_sessions()
        created = s.get(sid)
        if not created:
            return False
        if time.time() - created > SESSION_TTL:
            s.pop(sid, None)
            _save_sessions(s)
            return False
        return True


def register_session(sid: str):
    with SESSION_LOCK:
        s = _load_sessions()
        # Evict expired ones while we have the lock, so the store stays small.
        cutoff = time.time() - SESSION_TTL
        s = {k: v for k, v in s.items() if v > cutoff}
        if len(s) >= MAX_SESSIONS:
            oldest = min(s, key=s.get)
            s.pop(oldest, None)
        s[sid] = int(time.time())
        _save_sessions(s)


def require_drop_token() -> tuple[str, bool]:
    """Authorize a request to a drop endpoint.

    Returns (session_id, is_new). Raises 404 on failure.

    A valid session cookie is accepted even without the token in the URL, which
    is what lets the upload form work without passing the secret on every POST.
    An un-cookied request must present the secret token in the URL or the
    X-PD-Token header; that mints a session cookie and writes it back.
    """
    sid = session_id()
    if session_valid(sid):
        return sid, False

    candidate = request.view_args.get("token", "") if request.view_args else ""
    if not candidate:
        candidate = request.headers.get("X-PD-Token", "")
    if candidate and check_token(candidate, TOKEN):
        sid = new_session()
        register_session(sid)
        return sid, True

    abort(404)


def batch_owned_by(bid: str, sid: str) -> bool:
    """True if this session created the batch, or has not claimed it yet.

    An unclaimed batch can be adopted by whoever reaches it first; a claimed
    one is off-limits. This is what stops the per-session file cap from being
    reset by simply inventing a new batch id.
    """
    marker = batch_dir(bid) / "owner"
    try:
        owner = marker.read_text().strip()
    except OSError:
        return True
    return owner == sid


def claim_batch(bid: str, sid: str):
    marker = batch_dir(bid) / "owner"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(sid)


# --------------------------------------------------------------------------
# batch journal
# --------------------------------------------------------------------------


def batch_dir(bid: str) -> Path:
    return BATCHES / bid


def record_upload(bid: str, name: str, original: str, size: int, scanned: str):
    d = batch_dir(bid)
    d.mkdir(parents=True, exist_ok=True)
    entry = {
        "name": name,
        "original": original,
        "size": size,
        "scanned": scanned,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    manifest = d / "manifest.jsonl"
    # Cap the manifest. On a phone that is never going to be read, and an
    # unbounded append-only file in a small partition is a slow-motion failure.
    if manifest.exists() and manifest.stat().st_size > 1_000_000:
        manifest.unlink(missing_ok=True)
    with open(manifest, "a") as fh:
        fh.write(json.dumps(entry) + "\n")
    return entry


def batch_files(bid: str) -> list[dict]:
    manifest = batch_dir(bid) / "manifest.jsonl"
    if not manifest.exists():
        return []
    out = []
    for line in manifest.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def batch_total(bid: str) -> int:
    return sum(f["size"] for f in batch_files(bid))


def batch_count(bid: str) -> int:
    return len(batch_files(bid))


def session_file_count(sid: str) -> int:
    """Total files this session has uploaded, across all of its batches.

    Counting a single batch would let the cap be reset just by sending a new
    ?batch= id, which makes MAX_FILES_PER_SESSION meaningless.
    """
    total = 0
    if not BATCHES.exists():
        return 0
    for d in BATCHES.iterdir():
        if not d.is_dir():
            continue
        try:
            if (d / "owner").read_text().strip() == sid:
                total += len(batch_files(d.name))
        except OSError:
            continue
    return total


# --------------------------------------------------------------------------
# media scan
# --------------------------------------------------------------------------


def scan_media(paths: list[str]) -> str:
    """Ask MediaProvider about these files. Returns the technique that stuck."""
    if not paths:
        return "none"
    try:
        proc = subprocess.run(
            ["bash", MEDIA_SCAN, *paths],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        log("media-scan timeout")
        return "timeout"
    except OSError as exc:
        log(f"media-scan failed: {exc}")
        return "unavailable"

    detail = (proc.stderr or proc.stdout or "").strip().splitlines()
    if detail:
        log("media-scan: " + " | ".join(detail[-6:]))
    return detail[-1].split(":")[0].removeprefix("scanned(") if detail else "unknown"


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------


@app.get("/")
def root():
    """Landing page.

    Deliberately accepts no token, in the path or the query string. An earlier
    version redirected on ?t=, which meant the token travelled through an
    access log on its way to becoming a path token. Useless convenience, real
    leak.
    """
    return PAGE_INDEX, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.get("/healthz")
def healthz():
    """Liveness probe.

    start.sh polls this over loopback, but the same endpoint is reachable from
    the tunnel. Authenticated or loopback callers get full diagnostics.
    """
    drop = request.headers.get("X-PD-Token", "")
    owner = request.args.get("k", "") or request.args.get("owner", "")
    is_local = request.remote_addr in {"127.0.0.1", "::1"}

    if is_local or check_token(drop, TOKEN) or (OWNER_OK and check_token(owner, OWNER_TOKEN)):
        free = disk_free()
        total = disk_total()
        stats = get_active_upload_stats()
        return jsonify(
            ok=True,
            dest=str(DEST),
            free=free,
            dest_size=total,
            used=max(0, total - free),
            reserve=RESERVE_BYTES,
            sessions=stats["uploaders"] if stats["active"] else len(batch_ids_active()),
            total_sessions=len(batch_ids_recent()),
            public_url=get_public_url(),
            lan_ip=get_lan_ip(),
            upload_stats=stats,
        )
    return jsonify(ok=True)


def batch_ids_active() -> set[str]:
    """Batches with file modifications within the last 120 seconds."""
    if not BATCHES.exists():
        return set()
    cutoff = time.time() - 120
    return {p.name for p in BATCHES.iterdir() if p.is_dir() and p.stat().st_mtime > cutoff}


def batch_ids_recent() -> set[str]:
    if not BATCHES.exists():
        return set()
    cutoff = time.time() - SESSION_TTL
    return {p.name for p in BATCHES.iterdir() if p.is_dir() and p.stat().st_mtime > cutoff}


@app.route("/api/stop", methods=["GET", "POST"])
@app.route("/stop", methods=["GET", "POST"])
def stop_endpoint():
    drop = request.headers.get("X-PD-Token", "") or request.args.get("token", "")
    owner = request.args.get("k", "") or request.args.get("owner", "")
    is_local = request.remote_addr in {"127.0.0.1", "::1", "localhost"}

    if not (is_local or check_token(drop, TOKEN) or (OWNER_OK and check_token(owner, OWNER_TOKEN))):
        abort(403)

    def do_shutdown():
        time.sleep(0.3)
        try:
            subprocess.run(["pkill", "-9", "-f", "cloudflared"], check=False)
        except Exception:
            pass
        try:
            (EXPORT / "public-url.txt").unlink(missing_ok=True)
            (HOME / "url").unlink(missing_ok=True)
            (Path.home() / ".photo-drop" / "url").unlink(missing_ok=True)
            (EXPORT / "heartbeat").unlink(missing_ok=True)
        except Exception:
            pass
        try:
            subprocess.run(["termux-wake-unlock"], check=False)
        except Exception:
            pass
        os._exit(0)

    import threading
    threading.Thread(target=do_shutdown, daemon=True).start()
    return jsonify(ok=True, message="stopping")


@app.get("/d/<token>/")
def drop_page(token: str):
    sid, is_new = require_drop_token()
    free = disk_free()
    if free - RESERVE_BYTES <= 0:
        return PAGE_FULL, 200, {"Content-Type": "text/html; charset=utf-8"}
    resp = make_response(PAGE_UPLOAD.format(
        reserve=human(RESERVE_BYTES),
        max_mb=MAX_FILE_BYTES // (1024 * 1024),
        base=f"/d/{TOKEN}",
    ))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    if is_new:
        set_session_cookie(resp, sid)
    return resp


@app.get("/d/<token>/status")
def drop_status(token: str):
    sid, _ = require_drop_token()
    free = disk_free()
    bid = request.args.get("batch") or ""
    mine = bool(re.fullmatch(r"[a-f0-9]{6,32}", bid or "")) and batch_owned_by(bid, sid)
    return jsonify(
        free=free,
        free_human=human(free),
        usable=max(0, free - RESERVE_BYTES),
        uploaded=batch_count(bid) if mine else 0,
        reserve=RESERVE_BYTES,
        max_concurrent=MAX_CONCURRENT_UPLOADS,
    )


@app.post("/d/<token>/upload")
def upload(token: str):
    """Receive one file as the raw request body.

    The browser sends `xhr.send(file)` — no multipart envelope at all. That
    keeps the parser trivial, gives us Content-Length up front so we can reject
    a hopeless upload before a single byte lands, and preserves the native
    upload progress events the UI relies on.
    """
    sid, _ = require_drop_token()

    bid = request.args.get("batch") or uuid.uuid4().hex[:12]
    if not re.fullmatch(r"[a-f0-9]{6,32}", bid):
        abort(400)
    if not batch_owned_by(bid, sid):
        abort(403)
    if session_file_count(sid) >= MAX_FILES_PER_SESSION:
        return jsonify(ok=False, error="session file limit reached"), 409
    claim_batch(bid, sid)

    original = request.args.get("name") or "photo"
    declared = request.content_length

    if declared is None:
        return jsonify(ok=False, error="missing content length"), 411
    if declared > MAX_FILE_BYTES:
        return jsonify(ok=False, error="file is larger than the per-file limit"), 413
    # Reject before reading anything — the common failure is a full phone, and
    # there is no reason to write 40 GB into it first.
    if not enough_space(declared):
        return jsonify(ok=False, error="phone storage is full"), 507
    if disk_free_home() - 5_000_000 < RESERVE_BYTES // 4:
        return jsonify(ok=False, error="phone storage is full"), 507

    # Everything above this line is cheap bookkeeping. Everything below writes
    # to disk and shells out, so that is what the concurrency bound protects.
    if not _UPLOAD_SLOTS.acquire(blocking=False):
        log(f"upload refused, {MAX_CONCURRENT_UPLOADS} uploads already in flight")
        busy = jsonify(ok=False, error="phone is busy with other uploads, try again")
        busy.headers["Retry-After"] = "5"
        return busy, 503

    transfer_id = uuid.uuid4().hex[:8]
    with _ACTIVE_LOCK:
        _ACTIVE_TRANSFERS[transfer_id] = {
            "sid": sid,
            "bid": bid,
            "name": original,
            "size": declared or 0,
            "written": 0,
            "started": time.time(),
        }

    try:
        dest_dir = DEST
        dest_dir.mkdir(parents=True, exist_ok=True)
        name = unique_name(original, dest_dir)
        target = dest_dir / name
        tmp = dest_dir / f".{name}.part"

        written = 0
        try:
            with open(tmp, "wb") as out:
                while True:
                    chunk = request.stream.read(256 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_FILE_BYTES or not enough_space(written):
                        raise OSError("phone storage filled up mid-upload")
                    if written % (8 * 1024 * 1024) == 0 and disk_free_home() < RESERVE_BYTES // 4:
                        raise OSError("phone storage filled up mid-upload")
                    out.write(chunk)
            os.replace(tmp, target)
        except (OSError, ClientDisconnected) as exc:
            tmp.unlink(missing_ok=True)
            log(f"upload rejected ({original}): {exc}")
            return jsonify(ok=False, error=str(exc)), 507

        # Hand the file to MediaProvider so Google Photos sees it.
        scanned = scan_media([str(target)])
        entry = record_upload(bid, name, original, written, scanned)
        log(f"saved {original} -> {name} ({written}B, scan={scanned})")
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE_TRANSFERS.pop(transfer_id, None)
            if "written" in locals() and written > 0 and "target" in locals() and target.exists():
                _RECENT_UPLOADS.append({
                    "sid": sid,
                    "bid": bid,
                    "name": original,
                    "size": written,
                    "finished": time.time(),
                })
        # Released even when the write fails, so one bad upload cannot wedge
        # the server for the rest of the session.
        _UPLOAD_SLOTS.release()

    return jsonify(
        ok=True,
        batch=bid,
        scanned=scanned,
        free=disk_free(),
        files=[{"name": name, "size": written}],
    )


@app.get("/d/<token>/done/<batch>")
def done(token: str, batch: str):
    sid, is_new = require_drop_token()
    if not re.fullmatch(r"[a-f0-9]{6,32}", batch or ""):
        abort(400)
    if not batch_owned_by(batch, sid):
        abort(403)
    files = batch_files(batch)
    if not files:
        return redirect(f"/d/{TOKEN}/")

    unscanned = [f for f in files if f["scanned"] in {"scan-failed", "unavailable", "timeout", "none"}]
    rows = "\n".join(
        # `original` is the uploader's raw filename. It is NOT sanitised by
        # unique_name() — that only produces the on-disk name — so it must be
        # escaped here or it is a live XSS vector on this page.
        f'<li><span class="n">{escape(f["original"])}</span>'
        f'<span class="s">{human(f["size"])}</span></li>'
        for f in files
    )
    resp = make_response(PAGE_DONE.format(
        count=len(files),
        noun="file" if len(files) == 1 else "files",
        verb="is" if len(files) == 1 else "are",
        total=human(batch_total(batch)),
        rows=rows,
        thumbs=THUMBS.format(
            items="".join(
                f'<img loading="lazy" src="/d/{TOKEN}/file/{f["name"]}">'
                for f in files
                if f["name"].lower().endswith((".jpg", ".jpeg", ".png", ".webp", ".heic", ".gif"))
            )
        ),
        warning=(
            f"<p class=warn>{len(unscanned)} file(s) could not be handed to the phone's "
            "media library automatically. They are safely on the phone; open the Gallery "
            "app once and they will appear.</p>"
            if unscanned
            else ""
        ),
        token=TOKEN,
    ))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    if is_new:
        set_session_cookie(resp, sid)
    return resp


@app.get("/d/<token>/file/<name>")
def serve_file(token: str, name: str):
    _, _ = require_drop_token()
    if "/" in name or name in {"", ".", ".."}:
        abort(404)
    path = DEST / name
    if not path.is_file():
        abort(404)
    resp = send_file(path, conditional=True)
    resp.headers["Cache-Control"] = "private, max-age=86400"
    return resp


@app.get("/owner")
@app.get("/owner/<token>")
def owner_dashboard(token: str = ""):
    """Owner dashboard.

    Prefers the path form /owner/<token>. A query string (?k=...) ends up in
    access logs and Referer headers, so start.sh prints the path form and this
    keeps working as a fallback for a bookmarked URL.
    """
    supplied = token or request.args.get("k", "")
    if not OWNER_OK or not check_token(supplied, OWNER_TOKEN):
        abort(404)

    free = disk_free()
    recent = []
    if BATCHES.exists():
        for d in sorted(BATCHES.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if time.time() - d.stat().st_mtime > SESSION_TTL:
                continue
            files = batch_files(d.name)
            recent.append(
                f"<tr><td>{d.name}</td><td>{len(files)}</td>"
                f"<td>{human(batch_total(d.name))}</td>"
                f"<td>{datetime.fromtimestamp(d.stat().st_mtime).strftime('%H:%M:%S')}</td></tr>"
            )

    selftest = subprocess.run(
        ["bash", MEDIA_SCAN, "--selftest"], capture_output=True, text=True
    ).stdout.strip()

    return f"""<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Photo Drop — owner</title>
<style>
 body{{background:#0b0b0d;color:#e8e8ea;font:15px/1.5 -apple-system,system-ui,sans-serif;padding:20px;max-width:720px;margin:auto}}
 h1{{font-size:20px}} code{{background:#1a1a1e;padding:2px 6px;border-radius:4px;font-size:13px}}
 .box{{background:#151519;border:1px solid #26262c;border-radius:12px;padding:16px;margin:14px 0}}
 a{{color:#7cc4ff}} table{{width:100%;border-collapse:collapse;font-size:14px}}
 td{{padding:6px 8px;border-bottom:1px solid #26262c;text-align:left}}
 .bar{{height:8px;background:#26262c;border-radius:99px;overflow:hidden;margin-top:8px}}
 .fill{{background:{'#4ade80' if free-RESERVE_BYTES>RESERVE_BYTES else '#f87171'};height:100%}}
</style>
<h1>Photo Drop — owner</h1>
<div class=box>
  <b>Drop link</b><br><code>{request.host_url.rstrip('/')}/d/{TOKEN}</code><br>
  <span style="color:#888;font-size:13px">Send this to your friend. It is the credential — anyone with it can upload.</span>
</div>
<div class=box>
  <b>Destination</b> <code>{DEST}</code><br>
  <b>Free</b> {human(free)} · <b>reserve</b> {human(RESERVE_BYTES)}
  <div class=bar><div class=fill style="width:{min(100, free/disk_free()*100 if disk_free() else 0):.0f}%"></div></div>
</div>
<div class=box><b>Media scan capabilities</b><pre style="font-size:13px;color:#aaa">{selftest}</pre></div>
<div class=box><b>Recent uploads</b>
<table><tr><td>batch</td><td>files</td><td>size</td><td>at</td></tr>{''.join(recent) or '<tr><td colspan=4>none yet</td></tr>'}</table>
</div>"""


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# --------------------------------------------------------------------------
# pages
# --------------------------------------------------------------------------

PAGE_INDEX = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Photo Drop</title><style>
body{background:#0b0b0d;color:#e8e8ea;font:16px/1.6 -apple-system,system-ui,sans-serif;
display:grid;place-items:center;min-height:100vh;margin:0;padding:24px;text-align:center}
h1{font-size:22px;font-weight:600} p{color:#8a8a92;max-width:34ch}</style>
<h1>Photo Drop</h1><p>Open the link your friend sent you to send photos.</p>"""

PAGE_FULL = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Photo Drop</title><style>
body{background:#0b0b0d;color:#e8e8ea;font:16px/1.6 -apple-system,system-ui,sans-serif;
display:grid;place-items:center;min-height:100vh;margin:0;padding:24px;text-align:center}
h1{font-size:20px}p{color:#8a8a92;max-width:36ch}</style>
<h1>Phone storage is full</h1>
<p>The phone has run out of room, so uploads are paused. Nothing was lost. Try again shortly.</p>"""

THUMBS = '<div class="grid">{items}</div>'

PAGE_UPLOAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>Send Photos &amp; Videos — Photo Drop</title>
<style>
  :root {{
    --bg: #090a0f;
    --card: rgba(22, 24, 32, 0.85);
    --card-border: rgba(255, 255, 255, 0.08);
    --fg: #f3f4f6;
    --fg-muted: #9ca3af;
    --fg-subtle: #6b7280;
    --accent: #22c55e;
    --accent-glow: rgba(34, 197, 94, 0.25);
    --accent-dark: #15803d;
    --danger: #ef4444;
    --danger-bg: rgba(239, 68, 68, 0.12);
    --font: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  * {{ box-sizing: border-box; -webkit-tap-highlight-color: transparent; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--fg);
    font-family: var(--font);
    min-height: 100vh;
    padding: calc(env(safe-area-inset-top, 20px) + 16px) 16px calc(env(safe-area-inset-bottom, 20px) + 100px);
    overflow-x: hidden;
  }}
  .app-wrap {{
    max-width: 520px;
    margin: 0 auto;
  }}
  header {{
    margin-bottom: 20px;
  }}
  .brand {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }}
  .brand-icon {{
    width: 28px;
    height: 28px;
    background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
    border-radius: 8px;
    display: grid;
    place-items: center;
    box-shadow: 0 4px 12px var(--accent-glow);
  }}
  .brand-title {{
    font-size: 21px;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--fg);
  }}
  .sub {{
    color: var(--fg-muted);
    font-size: 13.5px;
    line-height: 1.45;
  }}
  .space-card {{
    background: var(--card);
    border: 1px solid var(--card-border);
    backdrop-filter: blur(16px);
    border-radius: 14px;
    padding: 12px 16px;
    margin-bottom: 18px;
  }}
  .space-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 13px;
    color: var(--fg-muted);
    margin-bottom: 8px;
  }}
  .space-header b {{
    color: var(--fg);
    font-weight: 600;
  }}
  .track {{
    height: 6px;
    background: rgba(255, 255, 255, 0.08);
    border-radius: 99px;
    overflow: hidden;
  }}
  .fill {{
    height: 100%;
    background: var(--accent);
    border-radius: 99px;
    transition: width 0.3s ease;
  }}
  .space-hint {{
    font-size: 11px;
    color: var(--fg-subtle);
    margin-top: 6px;
  }}
  .dropzone {{
    border: 2px dashed rgba(255, 255, 255, 0.16);
    background: rgba(255, 255, 255, 0.02);
    border-radius: 20px;
    padding: 36px 20px;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  }}
  .dropzone:active, .dropzone.dragover {{
    background: rgba(34, 197, 94, 0.06);
    border-color: var(--accent);
    transform: scale(0.99);
  }}
  .drop-icon {{
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.06);
    display: grid;
    place-items: center;
    margin: 0 auto 12px;
    color: var(--accent);
  }}
  .drop-title {{
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 4px;
    color: var(--fg);
  }}
  .drop-desc {{
    font-size: 13px;
    color: var(--fg-muted);
  }}
  .items-list {{
    margin-top: 20px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }}
  .file-item {{
    background: var(--card);
    border: 1px solid var(--card-border);
    backdrop-filter: blur(12px);
    border-radius: 14px;
    padding: 10px 14px;
    display: flex;
    align-items: center;
    gap: 12px;
    position: relative;
    overflow: hidden;
  }}
  .file-thumb {{
    width: 44px;
    height: 44px;
    border-radius: 8px;
    object-fit: cover;
    background: rgba(255, 255, 255, 0.05);
    flex-shrink: 0;
    display: grid;
    place-items: center;
    overflow: hidden;
  }}
  .file-thumb img {{
    width: 100%;
    height: 100%;
    object-fit: cover;
  }}
  .file-info {{
    flex: 1;
    min-width: 0;
  }}
  .file-name {{
    font-size: 13.5px;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--fg);
  }}
  .file-meta {{
    font-size: 12px;
    color: var(--fg-muted);
    margin-top: 2px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .file-progress {{
    position: absolute;
    bottom: 0;
    left: 0;
    height: 3px;
    background: var(--accent);
    width: 0%;
    transition: width 0.15s linear;
  }}
  .file-status {{
    font-size: 12px;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
    margin-left: auto;
    color: var(--fg-muted);
    flex-shrink: 0;
  }}
  .file-status.done {{
    color: var(--accent);
  }}
  .file-status.err {{
    color: var(--danger);
  }}
  .btn-remove {{
    background: none;
    border: none;
    color: var(--fg-subtle);
    padding: 6px;
    cursor: pointer;
    font-size: 16px;
    display: grid;
    place-items: center;
    border-radius: 6px;
    line-height: 1;
  }}
  .btn-remove:active {{
    background: rgba(255, 255, 255, 0.1);
    color: var(--fg);
  }}
  .btn-retry {{
    background: var(--danger-bg);
    border: 1px solid rgba(239, 68, 68, 0.3);
    color: var(--danger);
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 600;
  }}
  .bottom-bar {{
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    background: rgba(9, 10, 15, 0.92);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-top: 1px solid var(--card-border);
    padding: 12px 16px calc(env(safe-area-inset-bottom, 16px) + 12px);
    z-index: 100;
  }}
  .bottom-wrap {{
    max-width: 520px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }}
  .overall-track {{
    height: 4px;
    background: rgba(255, 255, 255, 0.1);
    border-radius: 99px;
    overflow: hidden;
    display: none;
  }}
  .overall-fill {{
    height: 100%;
    background: linear-gradient(90deg, #22c55e, #4ade80);
    width: 0%;
    transition: width 0.12s linear;
  }}
  .btn-send {{
    width: 100%;
    height: 52px;
    background: var(--fg);
    color: #090a0f;
    border: none;
    border-radius: 14px;
    font-family: var(--font);
    font-size: 16px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    cursor: pointer;
    box-shadow: 0 4px 16px rgba(255, 255, 255, 0.15);
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  }}
  .btn-send:disabled {{
    opacity: 0.35;
    cursor: not-allowed;
    box-shadow: none;
  }}
  .btn-send:not(:disabled):active {{
    transform: scale(0.98);
  }}
  .status-hint {{
    text-align: center;
    font-size: 12px;
    color: var(--fg-muted);
    min-height: 16px;
  }}
</style>
</head>
<body>
<div class="app-wrap">
  <header>
    <div class="brand">
      <div class="brand-icon">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 16V4m0 0L8 8m4-4 4 4"/><path d="M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>
        </svg>
      </div>
      <h1 class="brand-title">Send Photos &amp; Videos</h1>
    </div>
    <p class="sub">Transferred directly to Samsung Galaxy in original quality. Ready for Google Photos backup.</p>
  </header>

  <div class="space-card">
    <div class="space-header">
      <span>Phone Storage</span>
      <b><span id="free">Checking...</span> free</b>
    </div>
    <div class="track"><div class="fill" id="spacebar" style="width: 100%;"></div></div>
    <p class="space-hint">Uploads pause at {reserve} free to protect phone storage. Up to {max_mb} MB per file.</p>
  </div>

  <div class="dropzone" id="drop">
    <div class="drop-icon">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect width="18" height="18" x="3" y="3" rx="2" ry="2"/>
        <circle cx="9" cy="9" r="2"/>
        <path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/>
      </svg>
    </div>
    <div class="drop-title">Tap to Choose Photos &amp; Videos</div>
    <div class="drop-desc">Select as many as you like · HEIC, JPEG, MP4, MOV</div>
    <input type="file" id="pick" multiple accept="image/*,video/*" hidden>
  </div>

  <div class="items-list" id="items"></div>
</div>

<div class="bottom-bar">
  <div class="bottom-wrap">
    <div class="overall-track" id="overall-track">
      <div class="overall-fill" id="overall-fill"></div>
    </div>
    <button class="btn-send" id="go" disabled>
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/>
      </svg>
      <span id="go-text">Choose Photos to Send</span>
    </button>
    <div class="status-hint" id="status"></div>
  </div>
</div>

<script>
const BATCH = Math.random().toString(16).slice(2, 14);
const BASE = "{base}";
let queue = [];
let usableSpace = 0;
let isUploading = false;
let wakeLock = null;

async function requestWakeLock() {{
  if ("wakeLock" in navigator) {{
    try {{
      wakeLock = await navigator.wakeLock.request("screen");
    }} catch (e) {{}}
  }}
}}

function releaseWakeLock() {{
  if (wakeLock) {{
    try {{ wakeLock.release(); }} catch (e) {{}}
    wakeLock = null;
  }}
}}

async function poll() {{
  try {{
    const r = await fetch(BASE + "/status?batch=" + BATCH, {{ credentials: "same-origin" }});
    const d = await r.json();
    usableSpace = d.usable;
    document.getElementById("free").textContent = d.free_human;
    const pct = d.reserve ? (d.usable / (d.usable + d.reserve)) * 100 : 100;
    document.getElementById("spacebar").style.width = Math.max(2, Math.min(100, pct)) + "%";
  }} catch (e) {{}}
}}
poll();
setInterval(poll, 5000);

const drop = document.getElementById("drop");
const pick = document.getElementById("pick");
drop.onclick = () => {{ if (!isUploading) pick.click(); }};
pick.onchange = () => {{ addFiles([...pick.files]); pick.value = ""; }};

drop.ondragover = e => {{ e.preventDefault(); drop.classList.add("dragover"); }};
drop.ondragleave = () => {{ drop.classList.remove("dragover"); }};
drop.ondrop = e => {{
  e.preventDefault();
  drop.classList.remove("dragover");
  if (!isUploading && e.dataTransfer.files) {{
    addFiles([...e.dataTransfer.files]);
  }}
}};

function humanSize(bytes) {{
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}}

function addFiles(files) {{
  for (const f of files) {{
    const url = f.type.startsWith("image/") ? URL.createObjectURL(f) : "";
    queue.push({{
      file: f,
      previewUrl: url,
      loaded: 0,
      total: f.size,
      done: false,
      err: false,
      errMessage: ""
    }});
  }}
  renderQueue();
}}

function removeFile(index) {{
  if (isUploading) return;
  if (queue[index] && queue[index].previewUrl) {{
    URL.revokeObjectURL(queue[index].previewUrl);
  }}
  queue.splice(index, 1);
  renderQueue();
}}

function renderQueue() {{
  const container = document.getElementById("items");
  container.innerHTML = "";

  queue.forEach((it, idx) => {{
    const item = document.createElement("div");
    item.className = "file-item";

    let thumbHtml = "";
    if (it.previewUrl) {{
      thumbHtml = `<div class="file-thumb"><img src="${{it.previewUrl}}" alt="" loading="lazy"></div>`;
    }} else {{
      thumbHtml = `<div class="file-thumb">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>
        </svg>
      </div>`;
    }}

    let statusText = "";
    let statusClass = "file-status";
    if (it.done) {{
      statusText = "✓ Safe";
      statusClass += " done";
    }} else if (it.err) {{
      statusText = `<button class="btn-retry" onclick="retryFile(${{idx}})">Retry</button>`;
      statusClass += " err";
    }} else if (isUploading && it.loaded > 0) {{
      statusText = Math.round((it.loaded / it.total) * 100) + "%";
    }} else {{
      statusText = !isUploading ? `<button class="btn-remove" onclick="removeFile(${{idx}})">✕</button>` : "Ready";
    }}

    item.innerHTML = `
      ${{thumbHtml}}
      <div class="file-info">
        <div class="file-name">${{escapeHtml(it.file.name)}}</div>
        <div class="file-meta">
          <span>${{humanSize(it.file.size)}}</span>
          ${{it.err ? `<span style="color:var(--danger);">${{it.errMessage || "Upload failed"}}</span>` : ""}}
        </div>
      </div>
      <div class="${{statusClass}}">${{statusText}}</div>
      <div class="file-progress" style="width:${{it.done ? 100 : (it.loaded / it.total * 100)}}%;"></div>
    `;
    container.appendChild(item);
  }});

  const pending = queue.filter(i => !i.done);
  const doneCount = queue.filter(i => i.done).length;
  const goBtn = document.getElementById("go");
  const goText = document.getElementById("go-text");

  if (isUploading) {{
    goBtn.disabled = true;
    goText.textContent = `Uploading ${{doneCount + 1}} of ${{queue.length}}...`;
    document.getElementById("overall-track").style.display = "block";
  }} else if (pending.length > 0) {{
    goBtn.disabled = false;
    const totalBytes = pending.reduce((sum, i) => sum + i.file.size, 0);
    goText.textContent = `Send ${{pending.length}} ${{pending.length === 1 ? "File" : "Files"}} (${{humanSize(totalBytes)}})`;
    document.getElementById("overall-track").style.display = "none";
  }} else if (queue.length > 0 && doneCount === queue.length) {{
    goBtn.disabled = true;
    goText.textContent = "All Files Transferred!";
    document.getElementById("overall-track").style.display = "none";
  }} else {{
    goBtn.disabled = true;
    goText.textContent = "Choose Photos to Send";
    document.getElementById("overall-track").style.display = "none";
  }}
}}

function escapeHtml(text) {{
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}}

function updateOverallProgress() {{
  if (!queue.length) return;
  const total = queue.reduce((sum, i) => sum + i.total, 0);
  const loaded = queue.reduce((sum, i) => sum + (i.done ? i.total : i.loaded), 0);
  const pct = Math.min(100, Math.round((loaded / total) * 100));
  document.getElementById("overall-fill").style.width = pct + "%";
}}

async function uploadSingle(it) {{
  const url = BASE + "/upload?batch=" + BATCH + "&name=" + encodeURIComponent(it.file.name);
  const xhr = new XMLHttpRequest();
  const p = xhr.upload;

  p.onprogress = e => {{
    if (!e.lengthComputable) return;
    it.loaded = e.loaded;
    updateOverallProgress();
    renderQueue();
  }};

  await new Promise((resolve, reject) => {{
    p.onerror = () => reject(new Error("Connection dropped. Check Wi-Fi."));
    xhr.onload = () => {{
      if (xhr.status >= 200 && xhr.status < 300) {{
        resolve();
      }} else {{
        let msg = "Upload failed (" + xhr.status + ")";
        try {{
          const res = JSON.parse(xhr.responseText || "{{}}");
          if (res.error) msg = res.error;
        }} catch (_) {{}}
        reject(new Error(msg));
      }}
    }};
    xhr.open("POST", url);
    xhr.send(it.file);
  }});

  it.done = true;
  it.err = false;
  it.loaded = it.total;
}}

async function startUpload() {{
  if (isUploading) return;
  const pending = queue.filter(i => !i.done);
  if (!pending.length) return;

  isUploading = true;
  await requestWakeLock();
  document.getElementById("status").textContent = "Uploading... Keep this tab active.";
  renderQueue();

  for (const it of pending) {{
    if (usableSpace <= 0) {{
      document.getElementById("status").textContent = "Phone storage is full. Paused.";
      isUploading = false;
      releaseWakeLock();
      renderQueue();
      return;
    }}
    try {{
      await uploadSingle(it);
    }} catch (err) {{
      it.err = true;
      it.errMessage = err.message || "Failed";
    }}
    poll();
    renderQueue();
  }}

  isUploading = false;
  releaseWakeLock();

  const successCount = queue.filter(i => i.done).length;
  if (successCount > 0 && queue.every(i => i.done)) {{
    location.href = BASE + "/done/" + BATCH;
  }} else if (successCount > 0) {{
    document.getElementById("status").textContent = `${{successCount}} uploaded, some failed. Tap Retry to continue.`;
  }}
}}

function retryFile(idx) {{
  if (queue[idx]) {{
    queue[idx].err = false;
    queue[idx].errMessage = "";
    queue[idx].loaded = 0;
    renderQueue();
    startUpload();
  }}
}}

document.getElementById("go").onclick = startUpload;
</script>
</body></html>"""

PAGE_DONE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<title>Photos Received — Photo Drop</title>
<style>
  :root {{
    --bg: #090a0f;
    --card: rgba(22, 24, 32, 0.85);
    --card-border: rgba(255, 255, 255, 0.08);
    --fg: #f3f4f6;
    --fg-muted: #9ca3af;
    --accent: #22c55e;
    --accent-glow: rgba(34, 197, 94, 0.25);
    --font: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--fg);
    font-family: var(--font);
    min-height: 100vh;
    padding: calc(env(safe-area-inset-top, 24px) + 24px) 18px calc(env(safe-area-inset-bottom, 24px) + 24px);
    display: flex;
    flex-direction: column;
    align-items: center;
  }}
  .done-wrap {{
    max-width: 500px;
    width: 100%;
    margin: 0 auto;
    text-align: center;
  }}
  .tick-badge {{
    width: 64px;
    height: 64px;
    border-radius: 50%;
    background: var(--accent);
    color: #090a0f;
    display: grid;
    place-items: center;
    margin: 0 auto 16px;
    box-shadow: 0 8px 24px var(--accent-glow);
    animation: pop 0.4s cubic-bezier(0.16, 1, 0.3, 1);
  }}
  @keyframes pop {{
    0% {{ transform: scale(0.6); opacity: 0; }}
    100% {{ transform: scale(1); opacity: 1; }}
  }}
  h1 {{
    font-size: 22px;
    font-weight: 700;
    margin-bottom: 6px;
  }}
  .sub {{
    color: var(--fg-muted);
    font-size: 14.5px;
    line-height: 1.5;
    margin-bottom: 24px;
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 6px;
    margin-bottom: 24px;
    border-radius: 14px;
    overflow: hidden;
  }}
  .grid img {{
    width: 100%;
    aspect-ratio: 1;
    object-fit: cover;
    background: var(--card);
    display: block;
  }}
  .files-card {{
    background: var(--card);
    border: 1px solid var(--card-border);
    backdrop-filter: blur(12px);
    border-radius: 14px;
    padding: 6px 14px;
    margin-bottom: 24px;
    text-align: left;
  }}
  ul {{ list-style: none; }}
  li {{
    display: flex;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    font-size: 13.5px;
  }}
  li:last-child {{ border-bottom: none; }}
  li .n {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--fg); }}
  li .s {{ color: var(--fg-muted); flex-shrink: 0; font-variant-numeric: tabular-nums; }}
  .warn {{
    background: rgba(234, 179, 8, 0.12);
    border: 1px solid rgba(234, 179, 8, 0.3);
    color: #fef08a;
    padding: 12px;
    border-radius: 12px;
    font-size: 13px;
    margin-bottom: 20px;
    text-align: left;
  }}
  .actions {{
    display: flex;
    gap: 10px;
  }}
  .btn {{
    flex: 1;
    height: 48px;
    border-radius: 12px;
    font-family: var(--font);
    font-size: 15px;
    font-weight: 600;
    text-decoration: none;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    cursor: pointer;
  }}
  .btn-primary {{
    background: var(--accent);
    color: #090a0f;
    box-shadow: 0 4px 14px var(--accent-glow);
  }}
</style>
</head>
<body>
<div class="done-wrap">
  <div class="tick-badge">
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  </div>
  <h1>Your {count} {noun} {verb} safe</h1>
  <p class="sub">{total} received and stored in original quality on Samsung Galaxy.<br>Google Photos is backing them up now.</p>
  {thumbs}
  <div class="files-card">
    <ul>{rows}</ul>
  </div>
  {warning}
  <div class="actions">
    <a href="/d/{token}/" class="btn btn-primary">Send More Photos</a>
  </div>
</div>
</body></html>"""


# --------------------------------------------------------------------------
# boot
# --------------------------------------------------------------------------


def main():
    BATCHES.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)

    # A run killed mid-upload leaves .part files behind. They are invisible to
    # the gallery but they eat storage, so clear them out on boot.
    if DEST.exists():
        stale = [p for p in DEST.glob(".*.part") if p.is_file()]
        for p in stale:
            p.unlink(missing_ok=True)
        if stale:
            log(f"cleared {len(stale)} stale partial upload(s)")

    if not DEST.exists():
        print(f"\n  Destination {DEST} does not exist.")
        print("  Run:  termux-setup-storage   and pick the phone storage.\n")
        raise SystemExit(1)

    print(f"  photo-drop  ->  http://{HOST}:{PORT}/d/{TOKEN}")
    print(f"  destination ->  {DEST}")
    print(f"  free        ->  {human(disk_free())} (reserve {human(RESERVE_BYTES)})")
    app.run(host=HOST, port=PORT, threaded=True, debug=False)


if __name__ == "__main__":
    main()
