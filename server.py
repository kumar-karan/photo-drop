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

import concurrent.futures
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
from string import Template
from urllib.parse import quote

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
MAX_FILES_PER_SESSION = int(os.environ.get("PHOTO_DROP_MAX_FILES", "50000"))

# Concurrent uploads allowed at once. Flask's dev server spawns a thread per
# request, so without this a client could open hundreds of simultaneous
# multi-gigabyte writes and exhaust RAM, file descriptors or the disk write
# queue. Uploads queue with a timeout before refusing with 503, preventing
# transient rejection bursts.
MAX_CONCURRENT_UPLOADS = int(os.environ.get("PHOTO_DROP_MAX_CONCURRENT", "3"))
UPLOAD_ACQUIRE_TIMEOUT = float(os.environ.get("PHOTO_DROP_ACQUIRE_TIMEOUT", "5.0"))
_UPLOAD_SLOTS = threading.BoundedSemaphore(max(1, MAX_CONCURRENT_UPLOADS))
_SCAN_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="media-scan")

# How long a session cookie stays valid.
SESSION_TTL = int(os.environ.get("PHOTO_DROP_SESSION_TTL", str(12 * 3600)))

APP_VERSION = "1.7.0"
STARTED_AT = time.time()

_ACTIVE_LOCK = threading.Lock()
_ACTIVE_TRANSFERS = {}
_RECENT_UPLOADS = []
_SESSION_META = {}

# Keep the in-memory journal bounded. A phone that runs for weeks should not
# accumulate one record per upload forever.
MAX_RECENT_UPLOADS = 200
MAX_SESSION_META = 500
LIVE_STATE_WINDOW = int(os.environ.get("PHOTO_DROP_LIVE_WINDOW", str(6 * 3600)))


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def _age(ts: float, now: float | None = None) -> int:
    return max(0, int((now or time.time()) - ts))


def client_ip() -> str:
    """Best-effort client address, aware of the Cloudflare tunnel.

    Behind cloudflared every request reaches Flask from 127.0.0.1, so
    remote_addr alone would show every guest as "localhost". CF-Connecting-IP
    is set by Cloudflare; X-Forwarded-For covers the fallback path.
    """
    cf = (request.headers.get("CF-Connecting-IP") or "").strip()
    if cf:
        return cf
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return request.remote_addr or ""


def device_label(ua: str) -> str:
    """Turn a User-Agent into something a human can scan in one second."""
    text = (ua or "").lower()
    if "iphone" in text:
        device = "iPhone"
    elif "ipad" in text:
        device = "iPad"
    elif "android" in text:
        device = "Android"
    elif "macintosh" in text or "mac os x" in text:
        device = "Mac"
    elif "windows" in text:
        device = "Windows"
    elif "linux" in text:
        device = "Linux"
    else:
        device = "Browser"

    if "edg/" in text:
        browser = "Edge"
    elif "opr/" in text or "opera" in text:
        browser = "Opera"
    elif "firefox" in text:
        browser = "Firefox"
    elif "chrome" in text or "crios" in text:
        browser = "Chrome"
    elif "safari" in text:
        browser = "Safari"
    else:
        browser = "Browser"

    return f"{device} · {browser}"


def note_session(sid: str, created: float | None = None):
    """Remember who is behind a session and when they were last seen.

    Called on every authenticated drop request. The uploader page polls
    /status every few seconds, so last_seen is a real presence signal rather
    than a guess from batch mtimes.
    """
    if not sid:
        return
    now = time.time()
    is_new = False
    with _ACTIVE_LOCK:
        meta = _SESSION_META.get(sid)
        if meta is None:
            meta = {
                "created": created or now,
                "last_seen": now,
                "ip": "",
                "ua": "",
                "label": "Browser",
            }
            _SESSION_META[sid] = meta
            is_new = True
        meta["last_seen"] = now
        if created and created < meta.get("created", now):
            meta["created"] = created
        try:
            ip = client_ip()
            loopback = {"127.0.0.1", "::1"}
            # Prefer a real client address; only keep loopback if that is all
            # we have ever seen for this session.
            if ip and (not meta.get("ip") or meta["ip"] in loopback or ip not in loopback):
                meta["ip"] = ip
            ua = request.headers.get("User-Agent", "")
            if ua:
                label = device_label(ua)
                # A test client or a stripped header must not replace a real
                # device label with the generic fallback.
                if label != "Browser · Browser" or meta.get("label") in {None, "", "Browser"}:
                    meta["ua"] = ua[:300]
                    meta["label"] = label
        except RuntimeError:
            # No request context (disk reconstruction); keep what we have.
            pass
        if len(_SESSION_META) > MAX_SESSION_META:
            cutoff = now - SESSION_TTL
            stale = [k for k, v in _SESSION_META.items() if v.get("last_seen", 0) < cutoff]
            overflow = len(_SESSION_META) - MAX_SESSION_META
            if not stale:
                # Everything is fresh (a burst of guests). Evict the least
                # recently seen so the map still cannot grow without bound.
                stale = [k for k, _ in sorted(
                    _SESSION_META.items(), key=lambda item: item[1].get("last_seen", 0),
                )[:overflow]]
            for key in stale[:overflow]:
                _SESSION_META.pop(key, None)

    if is_new:
        # Persist outside the lock. The file is tiny, but the first request of
        # a session should not stall upload-progress reporting on disk I/O.
        _remember_session_meta(sid, dict(meta))


def start_transfer(sid: str, bid: str, name: str, size: int) -> str:
    transfer_id = uuid.uuid4().hex[:8]
    now = time.time()
    with _ACTIVE_LOCK:
        _ACTIVE_TRANSFERS[transfer_id] = {
            "id": transfer_id,
            "sid": sid,
            "bid": bid,
            "name": name,
            "size": int(size or 0),
            "written": 0,
            "started": now,
            "updated": now,
        }
    return transfer_id


def update_transfer(transfer_id: str, written: int):
    """Publish byte progress while a file is still being written.

    This is what makes the owner dashboard live. Without it the server only
    knows a transfer exists, not how far it has got, so the panel would sit at
    0% until the file was finished.
    """
    with _ACTIVE_LOCK:
        transfer = _ACTIVE_TRANSFERS.get(transfer_id)
        if transfer is not None:
            transfer["written"] = int(written)
            transfer["updated"] = time.time()


def finish_transfer(transfer_id: str, ok: bool):
    with _ACTIVE_LOCK:
        transfer = _ACTIVE_TRANSFERS.pop(transfer_id, None)
        if transfer and ok and transfer.get("written", 0) > 0:
            _RECENT_UPLOADS.append({
                "sid": transfer["sid"],
                "bid": transfer["bid"],
                "name": transfer["name"],
                "size": transfer["written"],
                "finished": time.time(),
            })
            if len(_RECENT_UPLOADS) > MAX_RECENT_UPLOADS:
                del _RECENT_UPLOADS[: len(_RECENT_UPLOADS) - MAX_RECENT_UPLOADS]


def get_active_upload_stats():
    with _ACTIVE_LOCK:
        now = time.time()
        # Keep a short tail for the uploader-side "recently received" chip, but
        # do not let the list grow without bound.
        _RECENT_UPLOADS[:] = [u for u in _RECENT_UPLOADS if (now - u["finished"]) < 300]

        in_flight = [dict(t) for t in _ACTIVE_TRANSFERS.values()]
        recent = [dict(u) for u in _RECENT_UPLOADS]

    active_sids = {u["sid"] for u in in_flight}
    recent_sids = {u["sid"] for u in recent if (now - u["finished"]) < 30}
    uploaders = len(active_sids | recent_sids)
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
        "in_flight": [
            {
                "name": u["name"],
                "size": u["size"],
                "written": u["written"],
                "pct": round(100 * u["written"] / u["size"]) if u["size"] else 0,
                "session": u["sid"][:6],
            }
            for u in in_flight
        ],
        "recent_count": len(recent),
        "recent_files": recent_names,
    }


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


def share_url() -> str:
    """The link to hand a guest.

    When the app shows the dashboard over loopback, request.host_url is
    `http://127.0.0.1:8080` — useless to a friend. Prefer the live tunnel,
    then the LAN address, and only fall back to the request host.
    """
    public = get_public_url()
    if public:
        return public.rstrip("/") + f"/d/{TOKEN}/"
    lan = get_lan_ip()
    if lan and lan != "127.0.0.1":
        return f"http://{lan}:{PORT}/d/{TOKEN}/"
    return request.host_url.rstrip("/") + f"/d/{TOKEN}/"


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

# Device identity for a session, kept beside the cookie store so a restart
# does not turn every known guest back into "Browser". This is advisory data
# (User-Agent and IP), never authentication.
SESSION_META_FILE = HOME / "session-meta.json"

# Upper bound on the store so a long-running phone can't grow it forever.
MAX_SESSIONS = 200

_SESSIONS_CACHE: dict[str, int] | None = None


def _load_sessions() -> dict:
    global _SESSIONS_CACHE
    if not SESSIONS.exists():
        _SESSIONS_CACHE = {}
        return {}
    try:
        data = json.loads(SESSIONS.read_text())
        if isinstance(data, dict):
            _SESSIONS_CACHE = data
            return data
    except (json.JSONDecodeError, OSError):
        pass
    if _SESSIONS_CACHE is not None:
        return dict(_SESSIONS_CACHE)
    return {}


def _save_sessions(data: dict):
    global _SESSIONS_CACHE
    _SESSIONS_CACHE = dict(data)
    # Atomic write so an ungraceful shutdown cannot leave a half-written JSON.
    try:
        tmp = SESSIONS.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(SESSIONS)
    except OSError as exc:
        log(f"could not persist sessions: {exc}")


# --------------------------------------------------------------------------
# high-watermark sync ledger
# --------------------------------------------------------------------------

SYNC_LEDGER_FILE = HOME / "sync_ledger.json"
LEDGER_LOCK = threading.Lock()
_LEDGER_CACHE: dict | None = None


def _load_ledger() -> dict:
    global _LEDGER_CACHE
    if not SYNC_LEDGER_FILE.exists():
        _LEDGER_CACHE = {"watermark": "", "files": {}}
        return _LEDGER_CACHE
    try:
        data = json.loads(SYNC_LEDGER_FILE.read_text())
        if isinstance(data, dict):
            data.setdefault("watermark", "")
            data.setdefault("files", {})
            _LEDGER_CACHE = data
            return data
    except (json.JSONDecodeError, OSError):
        pass
    if _LEDGER_CACHE is not None:
        return _LEDGER_CACHE
    return {"watermark": "", "files": {}}


def _save_ledger(data: dict):
    global _LEDGER_CACHE
    _LEDGER_CACHE = data
    try:
        tmp = SYNC_LEDGER_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(SYNC_LEDGER_FILE)
    except OSError as exc:
        log(f"could not persist sync ledger: {exc}")


def record_ledger_entry(name: str, original: str, size: int):
    with LEDGER_LOCK:
        ledger = _load_ledger()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        ledger["watermark"] = now_str
        ledger["files"][original] = {
            "name": name,
            "size": size,
            "synced_at": now_str,
        }
        _save_ledger(ledger)


def _load_session_meta() -> dict:
    try:
        data = json.loads(SESSION_META_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _remember_session_meta(sid: str, meta: dict):
    """Persist the label/IP for one session, pruned to the live window."""
    now = time.time()
    cutoff = now - SESSION_TTL
    with SESSION_LOCK:
        data = {
            key: value for key, value in _load_session_meta().items()
            if isinstance(value, dict) and value.get("last_seen", 0) >= cutoff
        }
        data[sid] = {
            "created": meta.get("created", now),
            "last_seen": meta.get("last_seen", now),
            "ip": meta.get("ip", ""),
            "label": meta.get("label", "Browser"),
        }
        if len(data) > MAX_SESSION_META:
            newest = sorted(data.items(), key=lambda item: item[1].get("last_seen", 0))
            data = dict(newest[-MAX_SESSION_META:])
        try:
            tmp = SESSION_META_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(data))
            tmp.replace(SESSION_META_FILE)
        except OSError as exc:
            log(f"could not persist session meta: {exc}")



def session_valid(sid: str) -> bool:
    if not sid or len(sid) < 16:
        return False
    with SESSION_LOCK:
        if _SESSIONS_CACHE is None:
            s = _load_sessions()
        else:
            s = _SESSIONS_CACHE
        created = s.get(sid)
        if not created:
            s = _load_sessions()
            created = s.get(sid)
            if not created:
                return False
        if time.time() - created > SESSION_TTL:
            s.pop(sid, None)
            _save_sessions(s)
            return False
        return True


def valid_session(sid: str) -> bool:
    """Back-compat alias kept for older callers/tests."""
    return session_valid(sid)


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
    Clients can also present their active session id in X-PD-Session or ?sid=
    to avoid fracturing images into separate sessions when cookies are partitioned.
    """
    sid = session_id()
    if not sid:
        sid = (request.headers.get("X-PD-Session") or "").strip()
    if not sid:
        sid = (request.args.get("sid") or "").strip()

    if sid and session_valid(sid):
        note_session(sid)
        return sid, False

    log(f"NEW_SESSION_MINTED: incoming_cookie={request.cookies.get(COOKIE)} sid={sid} view_args={request.view_args}")

    candidate = request.view_args.get("token", "") if request.view_args else ""
    if not candidate:
        candidate = request.headers.get("X-PD-Token", "")
    if candidate and check_token(candidate, TOKEN):
        sid = new_session()
        register_session(sid)
        note_session(sid)
        return sid, True

    abort(404)


BATCH_LOCK = threading.Lock()
_BATCH_OWNERS: dict[str, str] = {}


def batch_owned_by(bid: str, sid: str) -> bool:
    """True if this session created the batch, or has not claimed it yet.

    An unclaimed batch can be adopted by whoever reaches it first; a claimed
    one is off-limits. This is what stops the per-session file cap from being
    reset by simply inventing a new batch id.
    """
    with BATCH_LOCK:
        cached = _BATCH_OWNERS.get(bid)
        if cached is not None:
            return cached == sid
        marker = batch_dir(bid) / "owner"
        try:
            owner = marker.read_text().strip()
            if owner:
                _BATCH_OWNERS[bid] = owner
                return owner == sid
        except OSError:
            return True
        return True


def claim_batch(bid: str, sid: str):
    with BATCH_LOCK:
        _BATCH_OWNERS[bid] = sid
        marker = batch_dir(bid) / "owner"
        if marker.exists():
            return
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            tmp = marker.with_suffix(".tmp")
            tmp.write_text(sid)
            tmp.replace(marker)
        except OSError as exc:
            log(f"could not persist batch owner for {bid}: {exc}")


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
# live sessions
# --------------------------------------------------------------------------


def _new_session_record(sid: str, now: float) -> dict:
    return {
        "sid": sid,
        "created": now,
        "last_seen": now,
        "last_at": 0.0,
        "ip": "",
        "ua": "",
        "label": "Browser",
        "batches": set(),
        "files": 0,
        "bytes": 0,
        "recent_files": [],
        "last_file": "",
        "active": [],
        "connected": False,
        "is_test": False,
    }


def is_test_session(record: dict, sid: str = "") -> bool:
    """True if this session was generated by an automated test runner or probe."""
    ua = (record.get("ua") or "").lower()
    test_agents = ("pytest", "python-requests", "curl/", "httpie", "wget", "postman", "testclient", "urllib")
    if any(agent in ua for agent in test_agents):
        return True
    if sid.startswith("test-") or sid.startswith("anon-test") or "-test-" in sid:
        return True
    ip = (record.get("ip") or "").strip()
    if ip in ("127.0.0.1", "::1", "localhost") and not ("mozilla" in ua or "safari" in ua or "chrome" in ua):
        if any(tool in (record.get("label") or "").lower() for tool in ("curl", "pytest", "requests", "test")):
            return True
    return False


def merge_session_records(records: list[dict], now: float) -> dict:
    canonical = max(records, key=lambda r: (1 if r.get("connected") else 0, r.get("last_at", 0), r.get("last_seen", 0)))

    all_batches = set()
    for r in records:
        all_batches.update(r.get("batches", set()))

    total_files = 0
    total_bytes = 0
    seen_recent_names = set()
    all_recent = []

    if all_batches:
        for bname in sorted(all_batches):
            rows = batch_files(bname)
            total_files += len(rows)
            total_bytes += sum(int(f.get("size") or 0) for f in rows)
            for f in rows:
                fname = f.get("original") or f.get("name") or "file"
                if fname not in seen_recent_names:
                    seen_recent_names.add(fname)
                    all_recent.append({
                        "name": fname,
                        "size": int(f.get("size") or 0),
                        "at": f.get("at") or "",
                        "ts": f.get("ts", 0),
                    })
    else:
        total_files = sum(r.get("files", 0) for r in records)
        total_bytes = sum(r.get("bytes", 0) for r in records)
        for r in records:
            for f in r.get("recent_files", []):
                fname = f.get("name") or "file"
                if fname not in seen_recent_names:
                    seen_recent_names.add(fname)
                    all_recent.append(f)

    all_active = []
    seen_active_names = set()
    for r in records:
        for a in r.get("active", []):
            aname = a.get("name", "")
            if aname and aname not in seen_active_names:
                seen_active_names.add(aname)
                all_active.append(a)

    all_recent.sort(key=lambda x: x.get("ts", 0))

    last_file = ""
    if all_active:
        last_file = all_active[-1].get("name", "")
    elif all_recent:
        last_file = all_recent[-1].get("name", "")
    else:
        last_file = canonical.get("last_file", "")

    return {
        "sid": canonical["sid"],
        "created": min(r.get("created", now) for r in records),
        "last_seen": max(r.get("last_seen", now) for r in records),
        "last_at": max(r.get("last_at", 0) for r in records),
        "ip": canonical.get("ip") or next((r.get("ip") for r in records if r.get("ip")), ""),
        "ua": canonical.get("ua") or next((r.get("ua") for r in records if r.get("ua")), ""),
        "label": canonical.get("label") if canonical.get("label") != "Browser" else next((r.get("label") for r in records if r.get("label") != "Browser"), "Browser"),
        "batches": all_batches,
        "files": total_files,
        "bytes": total_bytes,
        "recent_files": all_recent[-5:],
        "last_file": last_file,
        "active": all_active,
        "connected": any(r.get("connected") for r in records),
        "is_test": all(r.get("is_test", False) for r in records),
    }


def deduplicate_session_records(records: list[dict], now: float) -> list[dict]:
    """Group and merge duplicate sessions from the same remote browser or test probe."""
    if not records:
        return []

    n = len(records)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int):
        root_i = find(i)
        root_j = find(j)
        if root_i != root_j:
            parent[root_j] = root_i

    for i in range(n):
        for j in range(i + 1, n):
            r1 = records[i]
            r2 = records[j]

            # Never merge test sessions with real guest sessions
            if r1.get("is_test") != r2.get("is_test"):
                continue

            if r1.get("is_test"):
                ua1 = (r1.get("ua") or "").lower()
                ua2 = (r2.get("ua") or "").lower()
                if (ua1 and ua2 and ua1 == ua2) or (r1.get("ip") and r1.get("ip") == r2.get("ip")):
                    union(i, j)
                continue

            # Real guest sessions:
            # 1. Share at least one batch ID
            if bool(r1.get("batches") and r2.get("batches") and (r1["batches"] & r2["batches"])):
                union(i, j)
                continue

            ip1 = (r1.get("ip") or "").strip()
            ip2 = (r2.get("ip") or "").strip()
            lbl1 = (r1.get("label") or "").strip()
            lbl2 = (r2.get("label") or "").strip()
            ua1 = (r1.get("ua") or "").strip()
            ua2 = (r2.get("ua") or "").strip()

            # 2. Same remote IP and device signature
            if ip1 and ip1 == ip2 and ip1 not in ("127.0.0.1", "::1", "localhost"):
                if (lbl1 and lbl1 == lbl2 and lbl1 != "Browser") or (ua1 and ua2 and ua1 == ua2):
                    union(i, j)
                    continue

            # 3. Same local network with identical browser User-Agent
            if ua1 and ua2 and ua1 == ua2 and "mozilla" in ua1.lower():
                union(i, j)
                continue

    groups: dict[int, list[dict]] = {}
    for i in range(n):
        root = find(i)
        groups.setdefault(root, []).append(records[i])

    merged = []
    for grp in groups.values():
        if len(grp) == 1:
            merged.append(grp[0])
        else:
            merged.append(merge_session_records(grp, now))
    return merged


def collect_sessions(now: float | None = None) -> list[dict]:
    """Merge cookie sessions, batch manifests and live transfers into one view.

    Three sources, deliberately:

    * sessions.json says who has a valid cookie, so a guest who just opened the
      link appears before they upload anything.
    * batch manifests are the durable record, so the dashboard survives a
      server restart.
    * the in-memory transfer map is the only place byte progress exists.

    Reading the manifests once per dashboard poll is cheap: a phone drop has
    tens of batches, not thousands.
    """
    now = now or time.time()
    cutoff = now - SESSION_TTL
    records: dict[str, dict] = {}

    def rec(sid: str) -> dict:
        record = records.get(sid)
        if record is None:
            record = _new_session_record(sid, now)
            records[sid] = record
        return record

    if BATCHES.exists():
        for d in BATCHES.iterdir():
            try:
                if not d.is_dir():
                    continue
                mtime = d.stat().st_mtime
            except OSError:
                continue
            if mtime < cutoff:
                continue
            try:
                sid = (d / "owner").read_text().strip()
            except OSError:
                sid = ""
            if not sid:
                sid = f"anon-{d.name[:6]}"
            record = rec(sid)
            record["batches"].add(d.name)
            rows = batch_files(d.name)
            record["files"] += len(rows)
            record["bytes"] += sum(int(f.get("size") or 0) for f in rows)
            record["last_seen"] = max(record["last_seen"], mtime)
            record["last_at"] = max(record["last_at"], mtime)
            if rows:
                record["last_file"] = rows[-1].get("original") or rows[-1].get("name") or ""
                for f in rows[-5:]:
                    record["recent_files"].append({
                        "name": f.get("original") or f.get("name") or "file",
                        "size": int(f.get("size") or 0),
                        "at": f.get("at") or _iso(mtime),
                        "ts": mtime,
                    })

    with SESSION_LOCK:
        stored = _load_sessions()
    for sid, created in stored.items():
        if not sid or created < cutoff:
            continue
        record = rec(sid)
        record["created"] = min(record["created"], created)
        record["last_seen"] = max(record["last_seen"], created)
        record["connected"] = True

    with _ACTIVE_LOCK:
        meta_items = {sid: dict(v) for sid, v in _SESSION_META.items() if v.get("last_seen", 0) >= cutoff}
        transfers = [dict(t) for t in _ACTIVE_TRANSFERS.values()]

    # After a restart memory is empty but the last-known identity is on disk.
    # Use it only for sessions memory does not know about, so live values win.
    for sid, meta in _load_session_meta().items():
        if not sid or sid in meta_items or meta.get("last_seen", 0) < cutoff:
            continue
        meta_items[sid] = meta

    for sid, meta in meta_items.items():
        record = rec(sid)
        record["created"] = min(record["created"], meta.get("created", record["created"]))
        record["last_seen"] = max(record["last_seen"], meta.get("last_seen", 0))
        if meta.get("ip"):
            record["ip"] = meta["ip"]
        if meta.get("label"):
            record["label"] = meta["label"]
        if meta.get("ua"):
            record["ua"] = meta["ua"]
        # A presence heartbeat is stronger evidence than a cookie issued hours
        # ago: the uploader page polls /status while it is open.
        if now - meta.get("last_seen", 0) < 45:
            record["connected"] = True

    for transfer in transfers:
        record = rec(transfer["sid"])
        size = int(transfer.get("size") or 0)
        written = int(transfer.get("written") or 0)
        elapsed = max(0.25, now - transfer.get("started", now))
        record["active"].append({
            "name": transfer.get("name") or "file",
            "size": size,
            "size_human": human(size),
            "written": written,
            "written_human": human(written),
            "pct": min(100, round(100 * written / size)) if size else 0,
            "bps": int(written / elapsed) if written else 0,
            "bps_human": f"{human(int(written / elapsed))}/s" if written else "",
            "started_age": _age(transfer.get("started", now), now),
        })
        record["last_seen"] = max(record["last_seen"], transfer.get("updated", now))
        record["last_at"] = max(record["last_at"], transfer.get("updated", now))
        record["last_file"] = transfer.get("name") or record["last_file"]

    raw_list = []
    for sid, record in records.items():
        if not (record["connected"] or record["files"] or record["active"]):
            continue
        record["is_test"] = is_test_session(record, sid)
        raw_list.append(record)

    deduped = deduplicate_session_records(raw_list, now)

    sessions = []
    for record in deduped:
        if record["active"]:
            state = "uploading"
        elif record["last_at"] and now - record["last_at"] < 60:
            state = "recent"
        elif record["connected"]:
            state = "connected"
        else:
            state = "idle"

        recent = sorted(record["recent_files"], key=lambda f: f.get("ts", 0))[-5:]
        sessions.append({
            "id": record["sid"][:6],
            "label": record["label"] or "Browser",
            "ip": record["ip"],
            "state": state,
            "connected": record["connected"],
            "created": _iso(record["created"]),
            "created_age": _age(record["created"], now),
            "last_seen": _iso(record["last_seen"]),
            "last_seen_age": _age(record["last_seen"], now),
            "files": record["files"],
            "bytes": record["bytes"],
            "bytes_human": human(record["bytes"]),
            "batches": sorted(record["batches"]),
            "active": record["active"],
            "recent": [
                {
                    "name": f.get("name") or "file",
                    "size": f.get("size") or 0,
                    "size_human": human(f.get("size") or 0),
                    "at": f.get("at") or "",
                    "ts": f.get("ts") or 0,
                }
                for f in recent
            ],
            "last_file": record["last_file"],
            "last_activity_age": _age(record["last_at"], now) if record["last_at"] else None,
            "is_test": record.get("is_test", False),
        })

    def sort_key(s: dict):
        test_prio = 1 if s.get("is_test") else 0
        if s["state"] == "uploading":
            return (test_prio, 0, s["last_seen_age"])
        if s["state"] == "recent":
            return (test_prio, 1, s["last_seen_age"])
        if s["state"] == "connected":
            return (test_prio, 2, s["last_seen_age"])
        return (test_prio, 3, s["last_seen_age"])

    sessions.sort(key=sort_key)
    return sessions


def build_owner_state() -> dict:
    now = time.time()
    all_sessions = collect_sessions(now)
    guest_sessions = [s for s in all_sessions if not s.get("is_test")]
    test_sessions = [s for s in all_sessions if s.get("is_test")]
    # Prioritize real guests in sessions display
    sessions = (guest_sessions + test_sessions)[:20]
    free = disk_free()
    total = disk_total()
    used = max(0, total - free) if total else 0
    stats = get_active_upload_stats()
    files = sum(s["files"] for s in all_sessions)
    uploaded_bytes = sum(s["bytes"] for s in all_sessions)
    recent = []
    for s in all_sessions:
        for f in s["recent"]:
            recent.append({
                "name": f["name"],
                "size": f["size"],
                "size_human": f["size_human"],
                "at": f["at"],
                "age": _age(f["ts"], now) if f.get("ts") else None,
                "session": s["id"],
                "label": s["label"],
            })
    recent.sort(key=lambda f: f["at"], reverse=True)

    guest_count = len(guest_sessions)
    reported_sessions = guest_count if guest_count or not test_sessions else len(all_sessions)

    return {
        "ok": True,
        "version": APP_VERSION,
        "now": _iso(now),
        "uptime_seconds": int(now - STARTED_AT),
        "uptime_human": _duration(int(now - STARTED_AT)),
        "server": {
            "pid": os.getpid(),
            "host": HOST,
            "port": PORT,
        },
        "storage": {
            "dest": str(DEST),
            "free": free,
            "free_human": human(free),
            "total": total,
            "total_human": human(total) if total else "unknown",
            "used": used,
            "used_human": human(used) if total else "unknown",
            "reserve": RESERVE_BYTES,
            "reserve_human": human(RESERVE_BYTES),
            "low": free <= RESERVE_BYTES,
            "free_pct": round(100 * free / total) if total else 0,
        },
        "network": {
            "public_url": get_public_url(),
            "lan_ip": get_lan_ip(),
        },
        "limits": {
            "max_file_bytes": MAX_FILE_BYTES,
            "max_file_human": human(MAX_FILE_BYTES),
            "max_files": MAX_FILES_PER_SESSION,
            "max_concurrent": MAX_CONCURRENT_UPLOADS,
        },
        "totals": {
            "sessions": reported_sessions,
            "guest_sessions": guest_count,
            "test_sessions": len(test_sessions),
            "total_sessions": len(all_sessions),
            "shown_sessions": len(sessions),
            "uploading_sessions": len({s["id"] for s in all_sessions if s["state"] == "uploading"}),
            "connected_sessions": len([s for s in (guest_sessions or all_sessions) if s["connected"]]),
            "files": files,
            "bytes": uploaded_bytes,
            "bytes_human": human(uploaded_bytes),
            "in_flight": stats["in_flight_count"],
            "uploaders": stats["uploaders"],
        },
        "sessions": sessions,
        "recent": recent[:12],
    }


def _duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"



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


def _scan_background(path: str, bid: str, name: str):
    """Notify MediaProvider asynchronously so HTTP upload responses return immediately."""
    try:
        scanned = scan_media([path])
        log(f"background scan: {name} -> {scanned}")
    except Exception as exc:
        log(f"background scan error ({name}): {exc}")


_SCAN_SELFTEST = {"at": 0.0, "text": ""}


def media_scan_selftest(force: bool = False) -> str:
    """Cache the capability probe; it shells out and is not cheap."""
    now = time.time()
    if not force and _SCAN_SELFTEST["text"] and now - _SCAN_SELFTEST["at"] < 300:
        return _SCAN_SELFTEST["text"]
    try:
        proc = subprocess.run(
            ["bash", MEDIA_SCAN, "--selftest"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        text = (proc.stdout or proc.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        text = f"selftest unavailable: {exc}"
    _SCAN_SELFTEST["at"] = now
    _SCAN_SELFTEST["text"] = text
    return text


@app.after_request
def _security_headers(resp):
    """Cheap hardening that applies to every response, HTML or JSON."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


def html_page(body: str, status: int = 200):
    resp = make_response(body, status)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    return resp



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
    return html_page(PAGE_INDEX)


def _is_direct_loopback() -> bool:
    """True only for a direct connection to the phone, not via the tunnel.

    cloudflared connects to 127.0.0.1 locally, so public internet traffic
    arrives with remote_addr == 127.0.0.1 too. remote_addr alone cannot
    distinguish the two. The tunnel sets X-Forwarded-* headers; a direct
    on-phone dial does not. Only trust loopback when no proxy headers exist.
    """
    if (request.headers.get("X-Forwarded-For")
            or request.headers.get("X-Forwarded-Host")
            or request.headers.get("X-Forwarded-Proto")):
        return False
    return request.remote_addr in {"127.0.0.1", "::1", "localhost"}


@app.get("/healthz")
def healthz():
    """Liveness probe.

    start.sh polls this over loopback with the drop token, and the same
    endpoint is reachable from the tunnel. Full diagnostics require a token:
    loopback alone is NOT trusted here, because tunnel traffic also arrives
    from 127.0.0.1. Unauthenticated callers get bare {"ok": true} — enough
    for a liveness check, nothing more.
    """
    drop = request.headers.get("X-PD-Token", "")
    owner = request.args.get("k", "") or request.args.get("owner", "")

    if check_token(drop, TOKEN) or (OWNER_OK and check_token(owner, OWNER_TOKEN)):
        free = disk_free()
        total = disk_total()
        stats = get_active_upload_stats()
        sessions = collect_sessions()
        guest_sessions = [s for s in sessions if not s.get("is_test")]
        test_sessions = [s for s in sessions if s.get("is_test")]
        guest_count = len(guest_sessions)
        reported_sessions = guest_count if guest_count or not test_sessions else len(sessions)
        with LEDGER_LOCK:
            ledger = _load_ledger()
        watermark = ledger.get("watermark") or ""
        total_synced = len(ledger.get("files", {}))
        if total_synced == 0 and DEST.exists():
            try:
                total_synced = len([f for f in DEST.iterdir() if f.is_file() and not f.name.startswith(".")])
            except OSError:
                pass
        return jsonify(
            ok=True,
            version=APP_VERSION,
            uptime=_age(STARTED_AT),
            dest=str(DEST),
            free=free,
            dest_size=total,
            used=max(0, total - free),
            reserve=RESERVE_BYTES,
            sessions=reported_sessions,
            guest_sessions=guest_count,
            test_sessions=len(test_sessions),
            total_sessions=len(sessions),
            active_sessions=len([s for s in sessions if s["state"] in {"uploading", "recent"}]),
            public_url=get_public_url(),
            lan_ip=get_lan_ip(),
            upload_stats=stats,
            watermark=watermark,
            total_synced=total_synced,
        )
    return jsonify(ok=True)


@app.route("/api/stop", methods=["GET", "POST"])
@app.route("/stop", methods=["GET", "POST"])
def stop_endpoint():
    drop = request.headers.get("X-PD-Token", "") or request.args.get("token", "")
    owner = request.args.get("k", "") or request.args.get("owner", "")
    # Direct on-phone loopback only (no tunnel proxy headers) may stop
    # unauthenticated — the foreground service's shutdown path relies on it.
    # Anyone arriving through cloudflared carries X-Forwarded-* and needs a token.
    is_local = _is_direct_loopback()

    if not (is_local or check_token(drop, TOKEN) or (OWNER_OK and check_token(owner, OWNER_TOKEN))):
        abort(403)

    def do_shutdown():
        time.sleep(0.3)
        # Termux's toybox pkill cannot see setsid'd processes, so scan /proc
        # directly for cloudflared by cmdline and kill by PID.
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as fh:
                        cmd = fh.read().decode("utf-8", "ignore")
                except OSError:
                    continue
                if "cloudflared tunnel" in cmd and "photo-drop/server.py" not in cmd:
                    try:
                        os.kill(int(pid), 9)
                    except OSError:
                        pass
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
        return html_page(PAGE_FULL)
    body = (
        PAGE_UPLOAD
        .replace("{{BASE}}", f"/d/{TOKEN}")
        .replace("{{RESERVE}}", human(RESERVE_BYTES))
        .replace("{{MAX_MB}}", str(MAX_FILE_BYTES // (1024 * 1024)))
        .replace("{{TOKEN}}", TOKEN)
    )
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    if is_new:
        set_session_cookie(resp, sid)
    return resp


@app.get("/d/<token>/status")
def drop_status(token: str):
    sid, is_new = require_drop_token()
    free = disk_free()
    bid = request.args.get("batch") or ""
    mine = bool(re.fullmatch(r"[a-f0-9]{6,32}", bid or "")) and batch_owned_by(bid, sid)
    with _ACTIVE_LOCK:
        active = [t for t in _ACTIVE_TRANSFERS.values() if t["sid"] == sid]
    resp = jsonify(
        free=free,
        free_human=human(free),
        usable=max(0, free - RESERVE_BYTES),
        uploaded=batch_count(bid) if mine else 0,
        session_files=session_file_count(sid),
        receiving=len(active),
        receiving_files=[t["name"] for t in active],
        session=sid[:6],
        sid=sid,
        reserve=RESERVE_BYTES,
        max_concurrent=MAX_CONCURRENT_UPLOADS,
        max_files=MAX_FILES_PER_SESSION,
        version=APP_VERSION,
    )
    if is_new:
        set_session_cookie(resp, sid)
    return resp


@app.get("/d/<token>/sync/status")
def sync_status(token: str):
    sid, is_new = require_drop_token()
    with LEDGER_LOCK:
        ledger = _load_ledger()
    free = disk_free()
    total_stored = len(ledger.get("files", {}))
    if total_stored == 0 and DEST.exists():
        try:
            total_stored = len([f for f in DEST.iterdir() if f.is_file() and not f.name.startswith(".")])
        except OSError:
            pass

    watermark = ledger.get("watermark")
    if not watermark:
        watermark = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    resp = jsonify(
        ok=True,
        watermark=watermark,
        total_synced=total_stored,
        free=free,
        free_human=human(free),
        usable=max(0, free - RESERVE_BYTES),
        version=APP_VERSION,
        session=sid[:6],
    )
    if is_new:
        set_session_cookie(resp, sid)
    return resp


@app.post("/d/<token>/sync/diff")
def sync_diff(token: str):
    sid, is_new = require_drop_token()
    req_data = request.get_json(silent=True) or {}
    candidates = req_data.get("items") or []

    with LEDGER_LOCK:
        ledger = _load_ledger()
    ledger_files = ledger.get("files", {})

    already_synced = []
    need_upload = []

    for item in candidates:
        name = item.get("name") or ""
        size = item.get("size") or 0
        if name in ledger_files:
            already_synced.append(name)
        elif DEST.exists() and (DEST / name).exists() and (DEST / name).stat().st_size == size:
            already_synced.append(name)
        else:
            need_upload.append(name)

    resp = jsonify(
        ok=True,
        watermark=ledger.get("watermark") or "",
        total_synced=len(ledger_files),
        already_synced=already_synced,
        need_upload=need_upload,
    )
    if is_new:
        set_session_cookie(resp, sid)
    return resp


@app.post("/d/<token>/upload")
def upload(token: str):
    """Receive one file as the raw request body.

    The browser sends `xhr.send(file)` — no multipart envelope at all. That
    keeps the parser trivial, gives us Content-Length up front so we can reject
    a hopeless upload before a single byte lands, and preserves the native
    upload progress events the UI relies on.
    """
    sid, is_new = require_drop_token()

    bid = request.args.get("batch") or uuid.uuid4().hex[:12]
    if not re.fullmatch(r"[a-f0-9]{6,32}", bid):
        abort(400)
    if not batch_owned_by(bid, sid):
        log(f"forbidden: batch {bid} not owned by session {sid}")
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
    if not _UPLOAD_SLOTS.acquire(blocking=True, timeout=UPLOAD_ACQUIRE_TIMEOUT):
        log(f"upload refused, {MAX_CONCURRENT_UPLOADS} uploads already in flight")
        busy = jsonify(ok=False, error="phone is busy with other uploads, try again")
        busy.headers["Retry-After"] = "5"
        return busy, 503

    transfer_id = start_transfer(sid, bid, original, declared or 0)
    saved = False

    try:
        dest_dir = DEST
        dest_dir.mkdir(parents=True, exist_ok=True)
        name = unique_name(original, dest_dir)
        target = dest_dir / name
        tmp = dest_dir / f".{name}.part"

        written = 0
        last_home_check = 0
        try:
            with open(tmp, "wb") as out:
                while True:
                    chunk = request.stream.read(256 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_FILE_BYTES or not enough_space(written):
                        raise OSError("phone storage filled up mid-upload")
                    if written - last_home_check >= 8 * 1024 * 1024:
                        last_home_check = written
                        if disk_free_home() < RESERVE_BYTES // 4:
                            raise OSError("phone storage filled up mid-upload")
                    out.write(chunk)
                    update_transfer(transfer_id, written)
            os.replace(tmp, target)
        except (OSError, ClientDisconnected) as exc:
            tmp.unlink(missing_ok=True)
            log(f"upload rejected ({original}): {exc}")
            return jsonify(ok=False, error=str(exc)), 507

        # Record upload and notify MediaProvider in background to avoid blocking
        # upload slots or timing out over mobile tunnels.
        record_upload(bid, name, original, written, "pending")
        record_ledger_entry(name, original, written)
        saved = True
        log(f"saved {original} -> {name} ({written}B)")
        try:
            _SCAN_EXECUTOR.submit(_scan_background, str(target), bid, name)
        except Exception as exc:
            log(f"failed to dispatch scan for {name}: {exc}")
    finally:
        finish_transfer(transfer_id, saved)
        # Released even when the write fails, so one bad upload cannot wedge
        # the server for the rest of the session.
        _UPLOAD_SLOTS.release()

    resp = jsonify(
        ok=True,
        batch=bid,
        scanned="pending",
        free=disk_free(),
        files=[{"name": name, "size": written}],
        session=sid[:6],
        sid=sid,
    )
    if is_new:
        set_session_cookie(resp, sid)
    return resp


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
    resp.headers["Cache-Control"] = "no-store"
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


def _owner_token_from_request(token: str = "") -> str:
    supplied = token or request.args.get("k", "") or request.headers.get("X-PD-Owner", "")
    if not OWNER_OK or not check_token(supplied, OWNER_TOKEN):
        abort(404)
    return supplied


def _owner_urls(token: str, supplied: str) -> tuple[str, str, str, str]:
    """Return API, clear-cache, clear-sessions and diagnostics URLs for the current auth form.

    The path form is preferred because query strings leak through logs and
    Referer headers. The query form stays for already-bookmarked links.
    """
    if token:
        base = f"/owner/{quote(token, safe='')}"
        return f"{base}/api/state", f"{base}/api/clear-parts", f"{base}/api/clear-sessions", f"{base}/api/diagnostics"
    key = quote(supplied, safe="")
    return (
        f"/owner/api/state?k={key}",
        f"/owner/api/clear-parts?k={key}",
        f"/owner/api/clear-sessions?k={key}",
        f"/owner/api/diagnostics?k={key}",
    )


@app.get("/owner")
@app.get("/owner/<token>")
def owner_dashboard(token: str = ""):
    """Owner console, live.

    Two hard requirements shaped this page:

    * It must work from inside the Android app over loopback, without the
      public tunnel. The app opens /owner/<token> directly.
    * It must show real sessions and real byte progress, not just a list of
      anonymous batch directories.

    The page is self-contained: no CDNs, no external fonts, no build step. A
    phone tunnel can be slow or offline; the dashboard still renders.
    """
    supplied = _owner_token_from_request(token)
    api_url, clear_url, clear_sessions_url, diag_url = _owner_urls(token, supplied)
    drop_url = share_url()
    state = build_owner_state()
    initial_json = json.dumps(state).replace("</", "<\\/")

    body = PAGE_OWNER.substitute(
        version=escape(APP_VERSION),
        dest=escape(str(DEST)),
        reserve=escape(human(RESERVE_BYTES)),
        max_mb=MAX_FILE_BYTES // (1024 * 1024),
        max_files=MAX_FILES_PER_SESSION,
        max_concurrent=MAX_CONCURRENT_UPLOADS,
        selftest=escape(media_scan_selftest()),
        api_url_js=json.dumps(api_url),
        clear_url_js=json.dumps(clear_url),
        clear_sessions_url_js=json.dumps(clear_sessions_url),
        diag_url_js=json.dumps(diag_url),
        drop_url_js=json.dumps(drop_url),
        drop_url_html=escape(drop_url),
        initial_state_json=initial_json,
    )
    return html_page(body)


@app.get("/owner/api/state")
@app.get("/owner/<token>/api/state")
def owner_state(token: str = ""):
    _owner_token_from_request(token)
    resp = jsonify(build_owner_state())
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/owner/api/clear-parts")
@app.post("/owner/<token>/api/clear-parts")
def owner_clear_parts(token: str = ""):
    """Delete orphaned .part files, but never an upload that is still writing.

    Only files older than five minutes are eligible. A live transfer keeps
    touching its .part file, so this cannot race a guest who is mid-upload.
    """
    _owner_token_from_request(token)
    now = time.time()
    removed = 0
    freed = 0
    skipped = 0
    if DEST.exists():
        for path in DEST.glob(".*.part"):
            try:
                if not path.is_file():
                    continue
                age = now - path.stat().st_mtime
                if age < 300:
                    skipped += 1
                    continue
                size = path.stat().st_size
                path.unlink()
                removed += 1
                freed += size
            except OSError:
                continue
    log(f"owner cleared {removed} stale partial(s), {freed}B")
    return jsonify(ok=True, removed=removed, bytes=freed, bytes_human=human(freed), skipped=skipped)


@app.post("/owner/api/clear-sessions")
@app.post("/owner/<token>/api/clear-sessions")
def owner_clear_sessions(token: str = ""):
    """Clear stale session history and batches."""
    _owner_token_from_request(token)
    with SESSION_LOCK:
        global _SESSIONS_CACHE
        _SESSIONS_CACHE = {}
        if SESSIONS.exists():
            SESSIONS.unlink(missing_ok=True)
        if SESSION_META_FILE.exists():
            SESSION_META_FILE.unlink(missing_ok=True)

    with _ACTIVE_LOCK:
        _SESSION_META.clear()

    with BATCH_LOCK:
        _BATCH_OWNERS.clear()

    removed_batches = 0
    if BATCHES.exists():
        for d in list(BATCHES.iterdir()):
            try:
                if d.is_dir():
                    shutil.rmtree(d, ignore_errors=True)
                    removed_batches += 1
            except OSError:
                pass

    log(f"owner cleared sessions and {removed_batches} batch(es)")
    return jsonify(ok=True, removed_batches=removed_batches)


@app.get("/owner/api/diagnostics")
@app.get("/owner/<token>/api/diagnostics")
def owner_diagnostics(token: str = ""):
    _owner_token_from_request(token)
    tail = []
    log_path = LOGS / "photo-drop.log"
    try:
        if log_path.exists():
            with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
                tail = fh.readlines()[-100:]
    except OSError:
        pass
    payload = {
        "state": build_owner_state(),
        "media_scan_selftest": media_scan_selftest(),
        "log_tail": [line.rstrip("\n") for line in tail],
    }
    resp = make_response(json.dumps(payload, indent=2))
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Disposition"] = 'attachment; filename="photo-drop-diagnostics.json"'
    return resp


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# --------------------------------------------------------------------------
# pages & templates
# --------------------------------------------------------------------------

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _read_template(filename: str) -> str:
    path = TEMPLATES_DIR / filename
    if path.exists():
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            pass
    return ""


# Templates loaded from templates/ folder with clean fallback
PAGE_OWNER = Template(_read_template("owner.html"))
PAGE_INDEX = _read_template("index.html")
PAGE_FULL = _read_template("full.html")
PAGE_UPLOAD = _read_template("upload.html")
PAGE_DONE = _read_template("done.html")
THUMBS = '<div class="grid">{items}</div>'


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
