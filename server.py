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


def _owner_urls(token: str, supplied: str) -> tuple[str, str, str]:
    """Return API, clear-cache and diagnostics URLs for the current auth form.

    The path form is preferred because query strings leak through logs and
    Referer headers. The query form stays for already-bookmarked links.
    """
    if token:
        base = f"/owner/{quote(token, safe='')}"
        return f"{base}/api/state", f"{base}/api/clear-parts", f"{base}/api/diagnostics"
    key = quote(supplied, safe="")
    return (
        f"/owner/api/state?k={key}",
        f"/owner/api/clear-parts?k={key}",
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
    api_url, clear_url, diag_url = _owner_urls(token, supplied)
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
# pages
# --------------------------------------------------------------------------

# The owner console is a Template rather than an f-string because it contains
# a lot of CSS and JavaScript braces. Dollar placeholders keep the markup
# readable and make accidental interpolation obvious.
PAGE_OWNER = Template("""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light">
<meta name="theme-color" content="#f9f9ff">
<title>Photo Drop — Live</title>
<style>
  :root {
    --bg: #f9f9ff;
    --surface: #ffffff;
    --surface-low: #f1f3ff;
    --surface-mid: #e9edff;
    --surface-high: #e1e8fd;
    --ink: #141b2b;
    --muted: #3e4943;
    --faint: #6e7a73;
    --line: #dce2f7;
    --line-soft: #edf0fa;
    --primary: #005d42;
    --primary-soft: #e6f4ea;
    --primary-tint: #97f5cc;
    --accent: #904d00;
    --accent-soft: #ffdcc3;
    --danger: #ba1a1a;
    --danger-soft: #ffdad6;
    --shadow: 0 1px 2px rgba(20, 27, 43, .05), 0 8px 24px rgba(20, 27, 43, .05);
    --radius: 18px;
    --font: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body { margin: 0; padding: 0; background: var(--bg); }
  body {
    color: var(--ink);
    font-family: var(--font);
    font-size: 15px;
    line-height: 1.45;
    min-height: 100vh;
    padding: calc(env(safe-area-inset-top, 0px) + 18px) 16px calc(env(safe-area-inset-bottom, 0px) + 28px);
  }
  .wrap { max-width: 720px; margin: 0 auto; }
  .top { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 16px; }
  .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .logo {
    width: 42px; height: 42px; border-radius: 13px; flex: 0 0 auto;
    background: linear-gradient(145deg, #047857 0%, #005d42 100%);
    color: #fff; display: grid; place-items: center;
    box-shadow: 0 6px 16px rgba(0, 93, 66, .22);
  }
  .brand h1 { font-size: 17px; line-height: 1.15; margin: 0; letter-spacing: -.02em; }
  .brand p { margin: 2px 0 0; color: var(--faint); font-size: 11.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; }
  .live { display: inline-flex; align-items: center; gap: 6px; flex: 0 0 auto; padding: 5px 10px; border-radius: 99px; background: var(--surface-mid); color: var(--primary); font-size: 11.5px; font-weight: 700; }
  .live.offline { background: var(--danger-soft); color: var(--danger); }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--primary); box-shadow: 0 0 0 4px rgba(0, 93, 66, .1); animation: pulse 1.8s ease-in-out infinite; }
  .live.offline .dot { background: var(--danger); box-shadow: none; animation: none; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }

  .hero { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px; box-shadow: var(--shadow); margin-bottom: 20px; }
  .hero-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
  .eyebrow { margin: 0 0 5px; color: var(--faint); font-size: 10.5px; font-weight: 800; letter-spacing: .12em; }
  .hero h2 { margin: 0; font-size: 23px; line-height: 1.15; letter-spacing: -.03em; }
  .hero-sub { margin: 6px 0 0; color: var(--muted); font-size: 13px; }
  .hero-badge { flex: 0 0 auto; border-radius: 99px; padding: 5px 10px; background: var(--primary-soft); color: var(--primary); font-size: 11px; font-weight: 800; letter-spacing: .04em; }
  .hero-badge.warn { background: var(--danger-soft); color: var(--danger); }
  .storage { margin-top: 16px; }
  .storage-row { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; color: var(--muted); font-size: 12px; margin-bottom: 7px; }
  .storage-row b { color: var(--ink); font-size: 13px; }
  .bar { position: relative; height: 9px; border-radius: 99px; background: var(--surface-high); overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 99px; background: linear-gradient(90deg, #047857, #10a06d); transition: width .35s ease; }
  .bar-reserve { position: absolute; top: -2px; bottom: -2px; width: 2px; background: var(--accent); opacity: .7; transition: left .35s ease; }
  .storage-hint { display: flex; justify-content: space-between; gap: 10px; margin-top: 6px; color: var(--faint); font-size: 11px; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-top: 14px; }
  .stat { background: var(--surface-low); border-radius: 12px; padding: 10px; min-width: 0; }
  .stat-label { display: block; color: var(--faint); font-size: 10.5px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; }
  .stat-value { display: block; margin-top: 2px; font-size: 19px; font-weight: 800; line-height: 1.1; font-variant-numeric: tabular-nums; }
  .stat-sub { display: block; color: var(--faint); font-size: 11px; margin-top: 1px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 10px; margin: 20px 2px 9px; }
  .section-head h2 { margin: 0; font-size: 13px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
  .section-head span { color: var(--faint); font-size: 11.5px; font-weight: 600; }
  .sessions { display: flex; flex-direction: column; gap: 10px; }
  .session { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; padding: 14px; box-shadow: var(--shadow); }
  .session.state-uploading { border-color: #b7dfc4; box-shadow: 0 0 0 2px rgba(4, 120, 87, .07), var(--shadow); }
  .s-top { display: flex; align-items: center; gap: 10px; }
  .avatar { width: 38px; height: 38px; border-radius: 12px; flex: 0 0 auto; display: grid; place-items: center; background: var(--surface-mid); color: var(--primary); font-weight: 800; font-size: 15px; }
  .s-id { min-width: 0; flex: 1; }
  .s-name { font-size: 14.5px; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .s-meta { color: var(--faint); font-size: 11.5px; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .pill { flex: 0 0 auto; border-radius: 99px; padding: 4px 8px; font-size: 10.5px; font-weight: 800; letter-spacing: .02em; }
  .pill.uploading { background: var(--primary-soft); color: var(--primary); }
  .pill.recent { background: #e7f7ee; color: #0b6b42; }
  .pill.connected { background: var(--surface-mid); color: var(--primary); }
  .pill.idle { background: var(--surface-low); color: var(--faint); }
  .s-stats { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-top: 10px; color: var(--faint); font-size: 11.5px; }
  .s-stats b { color: var(--ink); font-size: 12.5px; }
  .active-list { margin-top: 10px; display: flex; flex-direction: column; gap: 8px; }
  .active-file { background: var(--surface-low); border-radius: 11px; padding: 9px 10px; }
  .active-top { display: flex; justify-content: space-between; gap: 8px; font-size: 12px; }
  .fname { min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-weight: 600; }
  .fsize { flex: 0 0 auto; color: var(--primary); font-weight: 700; font-variant-numeric: tabular-nums; }
  .mini-bar { height: 5px; border-radius: 99px; background: var(--surface-high); overflow: hidden; margin-top: 6px; }
  .mini-fill { height: 100%; border-radius: 99px; background: linear-gradient(90deg, #047857, #10a06d); transition: width .25s linear; }
  .active-sub { color: var(--faint); font-size: 10.5px; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .chips { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 10px; }
  .chip { max-width: 100%; border-radius: 99px; background: var(--surface-low); color: var(--muted); padding: 4px 8px; font-size: 10.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .empty { display: none; text-align: center; padding: 24px 14px; border: 1px dashed var(--line); border-radius: 16px; color: var(--faint); font-size: 13px; background: rgba(255,255,255,.55); }

  .card { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; padding: 14px; box-shadow: var(--shadow); }
  .muted { color: var(--faint); font-size: 12.5px; margin: 0; }
  .list { display: flex; flex-direction: column; gap: 0; padding: 4px 14px; }
  .activity { display: flex; align-items: center; gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--line-soft); min-width: 0; }
  .activity:last-child { border-bottom: none; }
  .activity-icon { width: 32px; height: 32px; flex: 0 0 auto; border-radius: 10px; background: var(--primary-soft); color: var(--primary); display: grid; place-items: center; }
  .activity-body { min-width: 0; flex: 1; }
  .activity-name { font-size: 12.5px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .activity-meta { color: var(--faint); font-size: 10.5px; margin-top: 1px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .activity-size { flex: 0 0 auto; color: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
  .activity-empty { padding: 16px 0; color: var(--faint); font-size: 12.5px; text-align: center; }

  .link-row { display: flex; align-items: stretch; gap: 8px; margin-top: 10px; }
  .link-row code { flex: 1; min-width: 0; background: var(--surface-low); border-radius: 10px; padding: 9px 10px; font-family: var(--mono); font-size: 11px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .row { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  .btn { appearance: none; border: 1px solid var(--line); background: var(--surface); color: var(--ink); border-radius: 10px; padding: 8px 12px; font: inherit; font-size: 12px; font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; gap: 6px; cursor: pointer; }
  .btn:active { transform: translateY(1px); }
  .btn.small { flex: 0 0 auto; background: var(--primary); border-color: var(--primary); color: #fff; }
  .btn.ghost { background: var(--surface-low); color: var(--muted); }
  .btn.danger { background: var(--danger-soft); border-color: #f2c0bc; color: var(--danger); }
  .btn:disabled { opacity: .5; }
  .sys { display: flex; flex-direction: column; gap: 9px; }
  .kv { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; font-size: 12.5px; color: var(--faint); }
  .kv b, .kv code { color: var(--ink); text-align: right; font-weight: 600; overflow-wrap: anywhere; }
  .kv code { font-family: var(--mono); font-size: 11px; }
  details { margin-top: 2px; }
  summary { cursor: pointer; color: var(--primary); font-size: 12px; font-weight: 700; }
  pre { margin: 8px 0 0; padding: 10px; background: var(--surface-low); border-radius: 10px; color: var(--muted); font-family: var(--mono); font-size: 10.5px; line-height: 1.5; white-space: pre-wrap; overflow-wrap: anywhere; }
  .danger-zone { margin-top: 20px; }
  .danger-zone b { font-size: 13px; }
  .danger-zone .row { margin-top: 8px; }
  footer { margin-top: 22px; text-align: center; color: var(--faint); font-size: 10.5px; line-height: 1.6; }
  @media (min-width: 640px) {
    .stats { grid-template-columns: repeat(3, 1fr); }
    .hero h2 { font-size: 26px; }
  }
  @media (prefers-reduced-motion: reduce) {
    .dot { animation: none; }
    .bar-fill, .bar-reserve, .mini-fill { transition: none; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <div class="logo" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 16V4m0 0L8 8m4-4 4 4"/><path d="M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>
        </svg>
      </div>
      <div>
        <h1>Photo Drop</h1>
        <p>Owner console</p>
      </div>
    </div>
    <div class="live" id="livePill"><span class="dot"></span><span id="liveText">Live</span></div>
  </header>

  <section class="hero">
    <div class="hero-top">
      <div>
        <p class="eyebrow">PHONE STATUS</p>
        <h2 id="heroTitle">Connecting…</h2>
        <p class="hero-sub" id="heroSub">Reading live state from the server.</p>
      </div>
      <div class="hero-badge" id="heroBadge">…</div>
    </div>
    <div class="storage">
      <div class="storage-row"><span><b id="freeText">--</b> free</span><span id="usedText">--</span></div>
      <div class="bar"><div class="bar-fill" id="freeBar" style="width:0%"></div><div class="bar-reserve" id="reserveBar" style="left:90%"></div></div>
      <div class="storage-hint"><span>Safety reserve $reserve</span><span id="pctText">--</span></div>
    </div>
    <div class="stats">
      <div class="stat"><span class="stat-label">Sessions</span><span class="stat-value" id="statSessions">0</span><span class="stat-sub" id="statConnected">0 connected</span></div>
      <div class="stat"><span class="stat-label">Receiving</span><span class="stat-value" id="statInflight">0</span><span class="stat-sub" id="statUploading">idle</span></div>
      <div class="stat"><span class="stat-label">Uploaded</span><span class="stat-value" id="statFiles">0</span><span class="stat-sub" id="statBytes">0 B</span></div>
    </div>
  </section>

  <div class="section-head"><h2>Live sessions</h2><span id="sessionCount">0</span></div>
  <div class="sessions" id="sessions"></div>
  <div class="empty" id="sessionsEmpty">
    <b>No one is connected yet.</b><br>
    Send the drop link below. Sessions and file progress appear here the moment a guest opens it.
  </div>

  <div class="section-head"><h2>Recent uploads</h2><span id="recentCount"></span></div>
  <div class="card list" id="recent"></div>

  <div class="section-head"><h2>Share</h2></div>
  <div class="card">
    <p class="muted">This link is the credential. Anyone who has it can upload while the server is running.</p>
    <div class="link-row">
      <code id="dropUrl">$drop_url_html</code>
      <button class="btn small" id="copyBtn" type="button">Copy</button>
    </div>
    <div class="row">
      <a class="btn ghost" href="$drop_url_html" target="_blank" rel="noopener">Open guest page</a>
      <span class="muted" id="copyState"></span>
    </div>
  </div>

  <div class="section-head"><h2>System</h2><span id="lastUpdated">just now</span></div>
  <div class="card sys">
    <div class="kv"><span>Destination</span><code>$dest</code></div>
    <div class="kv"><span>Storage</span><b id="sysStorage">--</b></div>
    <div class="kv"><span>Uptime</span><b id="sysUptime">--</b></div>
    <div class="kv"><span>Version</span><b>$version</b></div>
    <div class="kv"><span>Limits</span><span id="sysLimits">$max_mb MB per file · $max_files per session · $max_concurrent at once</span></div>
    <div class="kv"><span>Public URL</span><code id="sysPublic">--</code></div>
    <details>
      <summary>Media scan capabilities</summary>
      <pre>$selftest</pre>
    </details>
  </div>

  <div class="card danger-zone">
    <b>Housekeeping</b>
    <p class="muted" style="margin-top:4px">Remove stalled .part files older than 5 minutes. Active uploads are never touched.</p>
    <div class="row">
      <button class="btn ghost" id="clearBtn" type="button">Clear temp cache</button>
      <button class="btn ghost" id="diagBtn" type="button">Download diagnostics</button>
    </div>
    <p class="muted" id="houseState" style="margin-top:8px"></p>
  </div>

  <footer>
    Live over loopback in the app, or through the tunnel in a browser.<br>
    Owner token stays in this URL — treat it like the drop link.
  </footer>
</div>

<script>
(function () {
  "use strict";
  var state = $initial_state_json;
  var API = $api_url_js;
  var CLEAR = $clear_url_js;
  var DIAG = $diag_url_js;
  var DROP = $drop_url_js;
  var lastUpdate = Date.now();
  var online = true;

  function esc(value) {
    return String(value === null || value === undefined ? "" : value).replace(/[&<>"']/g, function (c) {
      return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
    });
  }

  function ageText(seconds) {
    if (seconds === null || seconds === undefined) return "just now";
    var s = Math.max(0, Math.floor(seconds));
    if (s < 5) return "just now";
    if (s < 60) return s + "s ago";
    var m = Math.floor(s / 60);
    if (m < 60) return m + "m ago";
    var h = Math.floor(m / 60);
    if (h < 24) return h + "h ago";
    return Math.floor(h / 24) + "d ago";
  }

  function stateLabel(stateName) {
    if (stateName === "uploading") return "Uploading";
    if (stateName === "recent") return "Just received";
    if (stateName === "connected") return "Connected";
    return "Idle";
  }

  function activityHtml(item) {
    return '<div class="activity">'
      + '<div class="activity-icon" aria-hidden="true">' + iconFile() + '</div>'
      + '<div class="activity-body">'
      + '<div class="activity-name">' + esc(item.name) + '</div>'
      + '<div class="activity-meta">' + esc(item.label || "Guest") + ' · ' + esc(item.session || "") + ' · ' + esc(ageText(item.age)) + '</div>'
      + '</div>'
      + '<div class="activity-size">' + esc(item.size_human) + '</div>'
      + '</div>';
  }

  function iconFile() {
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>';
  }

  function sessionHtml(s) {
    var active = "";
    if (s.active && s.active.length) {
      active = '<div class="active-list">' + s.active.map(function (f) {
        var pct = Math.max(0, Math.min(100, Number(f.pct) || 0));
        return '<div class="active-file">'
          + '<div class="active-top"><span class="fname">' + esc(f.name) + '</span><span class="fsize">' + pct + '%</span></div>'
          + '<div class="mini-bar"><div class="mini-fill" style="width:' + pct + '%"></div></div>'
          + '<div class="active-sub">' + esc(f.written_human) + ' of ' + esc(f.size_human)
          + (f.bps_human ? ' · ' + esc(f.bps_human) : '') + '</div>'
          + '</div>';
      }).join('') + '</div>';
    }
    var recent = "";
    if (s.recent && s.recent.length) {
      recent = '<div class="chips">' + s.recent.map(function (f) {
        return '<span class="chip">' + esc(f.name) + ' · ' + esc(f.size_human) + '</span>';
      }).join('') + '</div>';
    }
    var initial = (s.label || "G").trim().charAt(0).toUpperCase() || "G";
    var stateBadge = s.is_test
      ? '<span class="pill" style="background:rgba(148,163,184,0.15);color:#94a3b8;border:1px solid rgba(148,163,184,0.3)">Test Probe</span>'
      : '<span class="pill ' + esc(s.state) + '">' + esc(stateLabel(s.state)) + '</span>';
    var metaText = s.is_test
      ? 'Automated probe · ' + esc(s.ip || "local")
      : 'Guest ' + esc(s.id) + ' · ' + esc(s.ip || "unknown IP");
    return '<article class="session state-' + esc(s.state) + (s.is_test ? ' test-probe' : '') + '">'
      + '<div class="s-top">'
      + '<div class="avatar" aria-hidden="true">' + esc(initial) + '</div>'
      + '<div class="s-id"><div class="s-name">' + esc(s.label || "Browser") + '</div>'
      + '<div class="s-meta">' + metaText + '</div></div>'
      + stateBadge
      + '</div>'
      + '<div class="s-stats"><span><b>' + esc(s.files) + '</b> file' + (s.files === 1 ? '' : 's') + '</span>'
      + '<span><b>' + esc(s.bytes_human) + '</b> received</span>'
      + '<span>seen ' + esc(ageText(s.last_seen_age)) + '</span></div>'
      + active + recent
      + '</article>';
  }

  function render(s) {
    var totals = s.totals || {};
    var storage = s.storage || {};
    var sessions = s.sessions || [];
    var inFlight = Number(totals.in_flight) || 0;
    var uploading = Number(totals.uploading_sessions) || 0;

    var title = inFlight > 0
      ? "Receiving " + inFlight + (inFlight === 1 ? " file" : " files")
      : (Number(totals.connected_sessions) > 0 ? "Phone is online" : "Ready for a drop");
    document.getElementById("heroTitle").textContent = title;

    var sub = Number(totals.sessions) > 0
      ? totals.sessions + (totals.sessions === 1 ? " session" : " sessions") + " · "
        + (totals.files || 0) + " files · " + (totals.bytes_human || "0 B") + " received"
      : "No sessions yet. Share the link below when you are ready.";
    document.getElementById("heroSub").textContent = sub;

    var badge = document.getElementById("heroBadge");
    if (storage.low) {
      badge.textContent = "LOW STORAGE";
      badge.className = "hero-badge warn";
    } else if (inFlight > 0) {
      badge.textContent = "LIVE";
      badge.className = "hero-badge";
    } else {
      badge.textContent = "ONLINE";
      badge.className = "hero-badge";
    }

    document.getElementById("freeText").textContent = storage.free_human || "--";
    document.getElementById("usedText").textContent = storage.total
      ? (storage.used_human || "0 B") + " of " + storage.total_human
      : "storage unknown";
    var freePct = Math.max(0, Math.min(100, Number(storage.free_pct) || 0));
    document.getElementById("freeBar").style.width = freePct + "%";
    var reservePct = storage.total ? Math.min(100, 100 * (Number(storage.reserve) || 0) / Number(storage.total)) : 0;
    document.getElementById("reserveBar").style.left = Math.max(0, 100 - reservePct) + "%";
    document.getElementById("pctText").textContent = freePct + "% free";

    document.getElementById("statSessions").textContent = totals.sessions || 0;
    var connectedSub = (totals.connected_sessions || 0) + " connected";
    if (totals.test_sessions) {
      connectedSub += " · " + totals.test_sessions + " probe" + (totals.test_sessions === 1 ? "" : "s");
    }
    document.getElementById("statConnected").textContent = connectedSub;
    document.getElementById("statInflight").textContent = inFlight;
    document.getElementById("statUploading").textContent = uploading > 0
      ? uploading + (uploading === 1 ? " session" : " sessions")
      : "idle";
    document.getElementById("statFiles").textContent = totals.files || 0;
    document.getElementById("statBytes").textContent = totals.bytes_human || "0 B";

    var shownSessions = sessions.length;
    var guestCount = totals.guest_sessions !== undefined ? totals.guest_sessions : totals.sessions;
    var testCount = totals.test_sessions || 0;
    var label = guestCount + (guestCount === 1 ? " guest" : " guests");
    if (testCount > 0) {
      label += " · " + testCount + " probe" + (testCount === 1 ? "" : "s");
    }
    document.getElementById("sessionCount").textContent = shownSessions
      ? (shownSessions < (totals.total_sessions || totals.sessions)
          ? "showing " + shownSessions + " of " + (totals.total_sessions || totals.sessions) + " (" + label + ")"
          : label)
      : "none";
    document.getElementById("sessions").innerHTML = sessions.map(sessionHtml).join("");
    document.getElementById("sessionsEmpty").style.display = sessions.length ? "none" : "block";

    var recent = s.recent || [];
    document.getElementById("recentCount").textContent = recent.length ? "last " + recent.length : "";
    document.getElementById("recent").innerHTML = recent.length
      ? recent.map(activityHtml).join("")
      : '<div class="activity-empty">Nothing received yet.</div>';

    document.getElementById("sysStorage").textContent = (storage.free_human || "--") + " free of " + (storage.total_human || "--");
    document.getElementById("sysUptime").textContent = s.uptime_human || "--";
    var limits = s.limits || {};
    document.getElementById("sysLimits").textContent = (limits.max_file_human || "--") + " per file · "
      + (limits.max_files || "--") + " per session · " + (limits.max_concurrent || "--") + " at once";
    document.getElementById("sysPublic").textContent = (s.network && s.network.public_url) || "LAN only";
    lastUpdate = Date.now();
    renderFreshness();
  }

  function renderFreshness() {
    var seconds = Math.floor((Date.now() - lastUpdate) / 1000);
    document.getElementById("lastUpdated").textContent = online
      ? (seconds < 3 ? "live now" : "updated " + ageText(seconds))
      : "reconnecting…";
  }

  function renderPill() {
    var pill = document.getElementById("livePill");
    var text = document.getElementById("liveText");
    if (online) {
      pill.className = "live";
      text.textContent = "Live";
    } else {
      pill.className = "live offline";
      text.textContent = "Reconnecting";
    }
  }

  function refresh(force) {
    if (!force && document.hidden) return;
    fetch(API, {cache: "no-store", headers: {"Accept": "application/json"}})
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      })
      .then(function (next) {
        online = true;
        renderPill();
        render(next);
      })
      .catch(function () {
        online = false;
        renderPill();
        renderFreshness();
      });
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(area);
        ok ? resolve() : reject(new Error("copy failed"));
      } catch (error) {
        reject(error);
      }
    });
  }

  var copyBtn = document.getElementById("copyBtn");
  copyBtn.addEventListener("click", function () {
    copyText(DROP).then(function () {
      document.getElementById("copyState").textContent = "Copied to clipboard";
      copyBtn.textContent = "Copied";
      setTimeout(function () { copyBtn.textContent = "Copy"; }, 1800);
    }).catch(function () {
      document.getElementById("copyState").textContent = "Select the link above to copy manually.";
    });
  });

  var clearBtn = document.getElementById("clearBtn");
  var clearing = false;
  clearBtn.addEventListener("click", function () {
    if (clearing) return;
    if (clearBtn.getAttribute("data-confirm") !== "1") {
      clearBtn.setAttribute("data-confirm", "1");
      clearBtn.textContent = "Tap again to confirm";
      setTimeout(function () {
        if (clearBtn.getAttribute("data-confirm") !== "1") return;
        clearBtn.setAttribute("data-confirm", "0");
        clearBtn.textContent = "Clear temp cache";
      }, 3200);
      return;
    }
    clearBtn.setAttribute("data-confirm", "0");
    clearBtn.disabled = true;
    clearBtn.textContent = "Clearing…";
    clearing = true;
    fetch(CLEAR, {method: "POST"})
      .then(function (response) { return response.json(); })
      .then(function (result) {
        document.getElementById("houseState").textContent = result.removed
          ? "Removed " + result.removed + " stale file(s), freed " + result.bytes_human + "."
          : "No stale temp files found." + (result.skipped ? " " + result.skipped + " active file(s) left alone." : "");
        refresh(true);
      })
      .catch(function () {
        document.getElementById("houseState").textContent = "Could not clear temp files. Try again.";
      })
      .then(function () {
        clearing = false;
        clearBtn.disabled = false;
        clearBtn.textContent = "Clear temp cache";
      });
  });

  document.getElementById("diagBtn").addEventListener("click", function () {
    window.location.href = DIAG;
  });

  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) refresh(true);
  });

  renderPill();
  render(state);
  refresh(true);
  setInterval(function () { refresh(false); }, 1200);
  setInterval(renderFreshness, 1000);
})();
</script>
</body></html>""")

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

PAGE_UPLOAD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="theme-color" content="#F5F6F7">

  <title>PhotoDrop Sync — iPhone PWA & Samsung APK Studio</title>
  <!-- Google Fonts: Plus Jakarta Sans & JetBrains Mono -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: {
            sans: ['"Plus Jakarta Sans"', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'monospace'],
          },
          colors: {
            board: '#D8DAD9',
            appbg: '#F5F6F7',
            electric: '#1E50FF',
            lavender: {
              card: '#DECFFF',
              deep: '#CBB5FF'
            },
            butter: {
              card: '#FFF1B8',
              deep: '#FBE38E'
            },
            mint: {
              card: '#DFF2E6',
              deep: '#C5E8D2'
            },
            pillnav: '#141519'
          },
          boxShadow: {
            'phone': '0 26px 60px -12px rgba(20, 21, 25, 0.22), 0 0 0 10px #FFFFFF',
            'soft': '0 4px 20px -2px rgba(20, 21, 25, 0.05)',
            'pill': '0 10px 25px -4px rgba(20, 21, 25, 0.28)',
            'float': '0 4px 12px rgba(20, 21, 25, 0.08)'
          }
        }
      }
    }
  </script>
  <style>
    .tabular-nums {
      font-variant-numeric: tabular-nums;
    }
    /* Hide scrollbars inside phone frames for clean presentation */
    .no-scrollbar::-webkit-scrollbar {
      display: none;
    }
    .no-scrollbar {
      -ms-overflow-style: none;
      scrollbar-width: none;
    }
    @keyframes floatPulse {
      0%, 100% { transform: translateY(0px); }
      50% { transform: translateY(-2px); }
    }
    .animate-float {
      animation: floatPulse 3s ease-in-out infinite;
    }
    @media (max-width: 768px) {
      .studio-header {
        display: none !important;
      }
      .studio-main {
        padding: 0 !important;
        margin: 0 !important;
        max-width: 100% !important;
        width: 100% !important;
      }
      .device-shell {
        height: calc(100vh - 48px) !important;
        height: calc(100dvh - 48px) !important;
        border-radius: 0 !important;
        box-shadow: none !important;
        max-width: 100% !important;
        width: 100% !important;
        border: none !important;
      }
      .device-label {
        display: none !important;
      }
      .ios-hardware-bar {
        display: none !important;
      }
      .mobile-top-bar {
        display: flex !important;
      }
      #frame-iphone, #frame-samsung {
        max-width: 100% !important;
        width: 100% !important;
      }
    }
    @media (min-width: 769px) {
      .mobile-top-bar {
        display: none !important;
      }
    }
  </style>
</head>
<body class="bg-board text-zinc-900 font-sans antialiased min-h-screen flex flex-col selection:bg-electric selection:text-white">
  <input type="file" id="real-file-picker" multiple accept="image/*,video/*" style="display:none;" />

  <!-- Mobile Top Switcher Bar (Shown only on small screens) -->
  <div class="mobile-top-bar w-full py-2.5 px-4 bg-white/90 backdrop-blur-md border-b border-zinc-200/80 flex items-center justify-between z-30 sticky top-0">
    <div class="flex items-center gap-2">
      <div class="w-7 h-7 rounded-full bg-electric text-white flex items-center justify-center font-extrabold text-xs shadow-xs">PD</div>
      <span class="text-xs font-bold text-zinc-900">PhotoDrop</span>
      <span id="mobile-pill-free" class="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-zinc-100 text-zinc-600">Sync</span>
    </div>
    <div class="bg-zinc-100 p-0.5 rounded-full flex items-center">
      <button type="button" onclick="setViewportMode('iphone')" id="m-btn-iphone" class="px-3 py-1 rounded-full text-[11px] font-bold bg-white text-zinc-900 shadow-xs transition-all">iPhone PWA</button>
      <button type="button" onclick="setViewportMode('samsung')" id="m-btn-samsung" class="px-3 py-1 rounded-full text-[11px] font-bold text-zinc-500 transition-all">Samsung APK</button>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- QUIET STUDIO PRESENTATION BAR                                             -->
  <!-- ========================================================================= -->
  <header class="studio-header w-full max-w-6xl mx-auto px-4 pt-5 pb-2 flex flex-wrap items-center justify-between gap-3">
    <div class="flex items-center gap-3">
      <div class="w-9 h-9 rounded-full bg-electric text-white flex items-center justify-center font-extrabold text-sm shadow-sm">
        PD
      </div>
      <div>
        <div class="flex items-center gap-2">
          <h1 class="text-sm font-extrabold tracking-tight text-zinc-900">PhotoDrop Dual-Device Sync</h1>
          <span class="text-[11px] font-semibold px-2.5 py-0.5 rounded-full bg-white/80 text-zinc-700">1-Tap Watermark Engine</span>
        </div>
        <p class="text-xs text-zinc-600">Interactive Live Link: Tap <strong>Sync All Now</strong> on iPhone to watch the Samsung APK receive files in real time</p>
      </div>
    </div>

    <!-- View Switcher & Quick Simulation Controls -->
    <div class="flex items-center flex-wrap gap-2">
      <div class="bg-white/75 backdrop-blur-sm p-1 rounded-full flex items-center gap-1 shadow-xs">
        <button type="button" onclick="setViewportMode('both')" id="view-btn-both"
          class="px-3.5 py-1.5 rounded-full text-xs font-bold bg-pillnav text-white transition-all">
          Side-by-Side
        </button>
        <button type="button" onclick="setViewportMode('iphone')" id="view-btn-iphone"
          class="px-3.5 py-1.5 rounded-full text-xs font-semibold text-zinc-600 hover:text-zinc-900 transition-all">
          iPhone PWA
        </button>
        <button type="button" onclick="setViewportMode('samsung')" id="view-btn-samsung"
          class="px-3.5 py-1.5 rounded-full text-xs font-semibold text-zinc-600 hover:text-zinc-900 transition-all">
          Samsung APK
        </button>
      </div>

      <button type="button" onclick="pickRealPhotos()"
        class="px-3.5 py-2 rounded-full bg-white hover:bg-zinc-50 active:scale-95 text-xs font-bold text-zinc-800 shadow-xs flex items-center gap-1.5 transition-all"
        title="Pick photos and videos from your camera roll">
        <span class="w-2 h-2 rounded-full bg-electric"></span>
        <span>+ Choose Photos</span>
      </button>

      <button type="button" onclick="resetDemoState()"
        class="px-3 py-2 rounded-full bg-white/60 hover:bg-white text-xs font-semibold text-zinc-600 transition-all">
        Reset (14)
      </button>
    </div>
  </header>

  <!-- ========================================================================= -->
  <!-- DUAL PHONE PRESENTATION STAGE                                             -->
  <!-- ========================================================================= -->
  <main class="studio-main flex-1 w-full max-w-6xl mx-auto px-4 py-5 flex flex-col lg:flex-row items-center lg:items-start justify-center gap-8 lg:gap-12">

    <!-- ======================================================================= -->
    <!-- DEVICE 1: APPLE IPHONE 17 PRO (PWA SENDER CLIENT)                       -->
    <!-- ======================================================================= -->
    <section id="frame-iphone" aria-label="iPhone 17 Pro PWA Client" class="w-full max-w-[380px] flex flex-col items-center">
      <!-- Subtle Device Label Above Phone -->
      <div class="device-label mb-3 flex items-center gap-2">
        <span class="px-3 py-1 rounded-full bg-white/80 text-[11px] font-bold tracking-wide uppercase text-zinc-700 shadow-xs">
          iOS Safari PWA &bull; Sender
        </span>
        <span class="text-xs font-medium text-zinc-600">iPhone 17 Pro</span>
      </div>

      <!-- Phone Hardware Shell -->
      <div class="device-shell w-full h-[790px] bg-appbg rounded-[46px] shadow-phone relative overflow-hidden flex flex-col justify-between select-none">
        
        <!-- Top iOS Status Bar + Dynamic Island -->
        <div class="ios-hardware-bar px-7 pt-3.5 pb-2 flex items-center justify-between text-xs font-bold text-zinc-900 z-20">
          <span class="tabular-nums">11:30</span>
          <!-- Dynamic Island -->
          <div class="w-24 h-6 bg-pillnav rounded-full flex items-center justify-between px-2.5">
            <span id="ios-island-indicator" class="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span id="ios-island-text" class="text-[9px] font-mono text-white/80 tabular-nums">SYNC</span>
          </div>
          <!-- Signal / Wifi / Battery -->
          <div class="flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 16 16"><rect x="1" y="10" width="2" height="4" rx="0.5"/><rect x="4.5" y="7.5" width="2" height="6.5" rx="0.5"/><rect x="8" y="5" width="2" height="9" rx="0.5"/><rect x="11.5" y="2" width="2" height="12" rx="0.5"/></svg>
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0"/></svg>
            <div class="w-5 h-2.5 rounded-[3px] border border-zinc-900 p-0.5 flex items-center"><div class="w-full h-full bg-zinc-900 rounded-[1px]"></div></div>
          </div>
        </div>

        <!-- SCROLLABLE VIEWPORT CONTAINER FOR IPHONE SCREENS -->
        <div class="flex-1 overflow-y-auto no-scrollbar px-5 pt-1 pb-24 relative">

          <!-- ================================================================= -->
          <!-- IPHONE SCREEN 1: HOME (1-Tap Catch-Up & Lavender Delta Card)      -->
          <!-- ================================================================= -->
          <div id="ios-screen-home" class="space-y-4">
            
            <!-- Top Profile & Bell Row -->
            <div class="flex items-center justify-between pt-1">
              <div class="flex items-center gap-3">
                <div class="w-11 h-11 rounded-full bg-[#D8F3DC] border-2 border-white shadow-xs overflow-hidden flex items-center justify-center">
                  <img src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&w=120&q=80" alt="Profile" class="w-full h-full object-cover" />
                </div>
                <div>
                  <div class="text-xs font-bold text-zinc-900">Hi, iPhone 17 Pro</div>
                  <div id="ios-header-status" class="text-[11px] font-medium text-zinc-500 tabular-nums">Samsung S24 &bull; 75% Free</div>
                </div>
              </div>
              <button type="button" onclick="switchIosTab('queue')"
                aria-label="Open Upload Queue"
                class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-700 hover:bg-zinc-100 transition-colors relative">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
                </svg>
                <span id="ios-bell-dot" class="w-2 h-2 rounded-full bg-electric absolute top-2 right-2.5"></span>
              </button>
            </div>

            <!-- Editorial Bold Title -->
            <h2 class="text-[26px] font-extrabold tracking-tight text-zinc-900 leading-tight">
              Sync With Samsung
            </h2>

            <!-- Search / Watermark Pill Bar -->
            <div class="bg-white rounded-full px-4 py-3 flex items-center justify-between shadow-soft">
              <div class="flex items-center gap-2.5 min-w-0">
                <span id="ios-tunnel-dot" class="w-2.5 h-2.5 rounded-full bg-emerald-500 flex-shrink-0"></span>
                <span id="ios-watermark-pill" class="text-xs font-medium text-zinc-500 truncate tabular-nums">
                  Watermark: Nov 8, 14:32:10
                </span>
              </div>
              <button type="button" onclick="switchIosTab('photos')" class="text-zinc-700 hover:text-electric transition-colors" title="Filter Unsynced Photos">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 6h9.75M10.5 6a1.5 1.5 0 11-3 0m3 0a1.5 1.5 0 10-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-9.75 0h9.75" />
                </svg>
              </button>
            </div>

            <!-- LAVENDER FEATURE CARD + FLOATING CONNECTOR PILL (Matches Top-Left Reference) -->
            <div class="relative pb-3">
              <div class="bg-lavender-card rounded-[26px] p-4 shadow-soft">
                <div class="flex items-center justify-between mb-3.5">
                  <span class="text-xs font-extrabold text-zinc-900">Unbacked Delta &amp; Library</span>
                  <button type="button" onclick="switchIosTab('photos')" class="text-zinc-700 hover:text-zinc-900">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
                    </svg>
                  </button>
                </div>

                <!-- 4 White Circular Icon Bubbles -->
                <div class="grid grid-cols-4 gap-2 text-center">
                  <!-- Bubble 1: Photos -->
                  <button type="button" onclick="switchIosTab('photos')" class="flex flex-col items-center group">
                    <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-xs group-hover:scale-105 transition-transform">
                      <span class="w-6 h-6 rounded-md bg-orange-100 text-orange-500 flex items-center justify-center">
                        <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z" clip-rule="evenodd"/></svg>
                      </span>
                    </div>
                    <span class="mt-2 text-[11px] font-bold text-zinc-900">Photos</span>
                    <span id="bubble-photos-sub" class="text-[10px] font-medium text-zinc-600 tabular-nums">10 New</span>
                  </button>

                  <!-- Bubble 2: Videos -->
                  <button type="button" onclick="switchIosTab('photos')" class="flex flex-col items-center group">
                    <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-xs group-hover:scale-105 transition-transform">
                      <span class="w-6 h-6 rounded-md bg-blue-100 text-electric flex items-center justify-center">
                        <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path d="M2 6a2 2 0 012-2h6a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V6zM14.553 7.106A1 1 0 0014 8v4a1 1 0 00.553.894l2 1A1 1 0 0018 13V7a1 1 0 00-1.447-.894l-2 1z"/></svg>
                      </span>
                    </div>
                    <span class="mt-2 text-[11px] font-bold text-zinc-900">Videos</span>
                    <span id="bubble-videos-sub" class="text-[10px] font-medium text-zinc-600 tabular-nums">2 New</span>
                  </button>

                  <!-- Bubble 3: ProRAW -->
                  <button type="button" onclick="switchIosTab('photos')" class="flex flex-col items-center group">
                    <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-xs group-hover:scale-105 transition-transform">
                      <span class="w-6 h-6 rounded-md bg-rose-100 text-rose-500 flex items-center justify-center font-mono text-[9px] font-extrabold">
                        RAW
                      </span>
                    </div>
                    <span class="mt-2 text-[11px] font-bold text-zinc-900">ProRAW</span>
                    <span id="bubble-raw-sub" class="text-[10px] font-medium text-zinc-600 tabular-nums">2 New</span>
                  </button>

                  <!-- Bubble 4: Already Synced -->
                  <button type="button" onclick="openSyncedFilter()" class="flex flex-col items-center group">
                    <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-xs group-hover:scale-105 transition-transform">
                      <span class="w-6 h-6 rounded-md bg-purple-100 text-purple-600 flex items-center justify-center">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg>
                      </span>
                    </div>
                    <span class="mt-2 text-[11px] font-bold text-zinc-900">Synced</span>
                    <span id="bubble-synced-sub" class="text-[10px] font-medium text-zinc-600 tabular-nums">4,806</span>
                  </button>
                </div>
              </div>

              <!-- Signature Floating Connector Pill ("420 Files • 5 Folder" in Reference) -->
              <div class="absolute -bottom-1.5 inset-x-0 flex justify-center">
                <div id="ios-connector-pill" class="px-4 py-1 rounded-full bg-white shadow-float border border-zinc-100 text-[10px] font-bold text-zinc-700 tabular-nums">
                  14 Unsynced Items &bull; 68.4 MB Delta
                </div>
              </div>
            </div>

            <!-- WARM BUTTER YELLOW HERO CARD (Matches "Viewed Links / See All ->" Card) -->
            <div class="bg-butter-card rounded-[26px] p-4 shadow-soft relative overflow-hidden">
              <!-- Decorative soft cloud shapes in top right -->
              <div class="w-20 h-20 rounded-full bg-white/50 absolute -top-6 -right-6 pointer-events-none"></div>
              <div class="w-12 h-12 rounded-full bg-white/60 absolute top-6 right-8 pointer-events-none"></div>

              <div class="relative z-10">
                <div class="flex items-center justify-between">
                  <span id="ios-hero-tag" class="text-[10px] font-extrabold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-white/80 text-zinc-800">
                    Mode A &bull; Auto Catch-Up
                  </span>
                  <span id="ios-hero-speed" class="text-[11px] font-mono font-bold text-zinc-700 tabular-nums hidden">
                    42.8 MB/s
                  </span>
                </div>

                <h3 id="ios-hero-title" class="mt-2.5 text-lg font-extrabold text-zinc-900 leading-snug">
                  14 New Photos Waiting
                </h3>
                <p id="ios-hero-desc" class="mt-1 text-xs font-medium text-zinc-600 leading-relaxed max-w-[235px]">
                  Captured after your last Samsung backup on Nov 8 at 2:32 PM.
                </p>

                <!-- Signature White Pill CTA Button with Black Circle Right Arrow -->
                <button type="button" onclick="triggerOneTapSync()" id="ios-hero-cta"
                  class="mt-4 w-full bg-white hover:bg-zinc-50 active:scale-[0.99] rounded-full pl-5 pr-2 py-2 flex items-center justify-between shadow-soft transition-all group">
                  <span id="ios-hero-cta-text" class="text-xs font-extrabold text-zinc-900 tabular-nums">
                    Back Up 14 Items Now
                  </span>
                  <span id="ios-hero-cta-icon" class="w-8 h-8 rounded-full bg-pillnav text-white flex items-center justify-center group-hover:translate-x-0.5 transition-transform">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                    </svg>
                  </span>
                </button>
              </div>
            </div>

            <!-- 3 Pastel Action Chips (Matches "Upload / Folder / Scan" in Center Screen) -->
            <div class="grid grid-cols-3 gap-2 pt-0.5">
              <button type="button" onclick="triggerOneTapSync()"
                class="py-2.5 px-3 rounded-full bg-[#DFF2E6] hover:brightness-95 text-zinc-900 text-xs font-bold flex items-center justify-center gap-1.5 transition-all">
                <svg class="w-3.5 h-3.5 text-emerald-700" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/></svg>
                <span>1-Tap</span>
              </button>
              <button type="button" onclick="switchIosTab('photos')"
                class="py-2.5 px-3 rounded-full bg-[#FADCE6] hover:brightness-95 text-zinc-900 text-xs font-bold flex items-center justify-center gap-1.5 transition-all">
                <svg class="w-3.5 h-3.5 text-rose-700" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg>
                <span>Select</span>
              </button>
              <button type="button" onclick="switchIosTab('queue')"
                class="py-2.5 px-3 rounded-full bg-[#DCEBFF] hover:brightness-95 text-zinc-900 text-xs font-bold flex items-center justify-center gap-1.5 transition-all">
                <svg class="w-3.5 h-3.5 text-electric" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z"/></svg>
                <span>Queue</span>
              </button>
            </div>

          </div>

          <!-- ================================================================= -->
          <!-- IPHONE SCREEN 2: PHOTOS (Matches Bottom-Left "Photos / Album")    -->
          <!-- ================================================================= -->
          <div id="ios-screen-photos" class="hidden space-y-4">
            <!-- Top Nav Header -->
            <div class="flex items-center justify-between pt-1">
              <button type="button" onclick="switchIosTab('home')"
                class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800 hover:bg-zinc-100">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18"/></svg>
              </button>
              <h2 class="text-base font-extrabold text-zinc-900">Selective Sync</h2>
              <button type="button" onclick="toggleSelectAllUnsynced()" id="ios-select-all-btn"
                class="px-3 h-9 rounded-full bg-white border border-zinc-200/80 text-[11px] font-bold text-electric hover:bg-zinc-50">
                All New
              </button>
            </div>

            <!-- Search / Filter Bar -->
            <div class="bg-white rounded-full px-4 py-2.5 flex items-center justify-between shadow-soft">
              <div class="flex items-center gap-2 text-xs text-zinc-500">
                <svg class="w-4 h-4 text-zinc-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/></svg>
                <span id="ios-photo-filter-summary">Skipping 4,806 already on Samsung</span>
              </div>
              <span class="text-[11px] font-mono font-bold text-emerald-600">SHA-256</span>
            </div>

            <!-- Segmented Pill Toggle ("Album" vs "Timeline" in Reference) -->
            <div class="grid grid-cols-2 gap-2.5">
              <button type="button" onclick="setPhotoFilter('unsynced')" id="seg-btn-unsynced"
                class="py-2.5 rounded-full text-xs font-bold bg-electric text-white shadow-xs transition-all tabular-nums">
                Unsynced (14)
              </button>
              <button type="button" onclick="setPhotoFilter('all')" id="seg-btn-all"
                class="py-2.5 rounded-full text-xs font-bold bg-white text-zinc-700 hover:bg-zinc-100 transition-all tabular-nums">
                All Library (18)
              </button>
            </div>

            <!-- 2-Column Rounded Photo Cards Grid (Matches Summer Memories / Paris Vacation) -->
            <div id="ios-photo-grid" class="grid grid-cols-2 gap-3 pt-1">
              <!-- Populated by JS -->
            </div>

            <!-- Sticky Action Button When Items Selected -->
            <div class="pt-1">
              <button type="button" onclick="syncSelectedPhotos()" id="ios-sync-selected-btn"
                class="w-full py-3.5 px-5 rounded-full bg-electric hover:bg-blue-700 active:scale-[0.99] text-white text-xs font-extrabold shadow-md flex items-center justify-between transition-all">
                <span id="ios-sync-selected-label" class="tabular-nums">Push 3 Selected Photos</span>
                <span id="ios-sync-selected-mb" class="font-mono text-[11px] opacity-90 tabular-nums">21.5 MB &rarr;</span>
              </button>
            </div>
          </div>

          <!-- ================================================================= -->
          <!-- IPHONE SCREEN 3: FILE UPLOAD QUEUE (Matches Bottom-Center Screen) -->
          <!-- ================================================================= -->
          <div id="ios-screen-queue" class="hidden space-y-4">
            <!-- Top Nav Header -->
            <div class="flex items-center justify-between pt-1">
              <button type="button" onclick="switchIosTab('home')"
                class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800 hover:bg-zinc-100">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18"/></svg>
              </button>
              <h2 class="text-base font-extrabold text-zinc-900">File Upload</h2>
              <button type="button" onclick="triggerOneTapSync()"
                class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800 hover:bg-zinc-100" title="Start All">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/></svg>
              </button>
            </div>

            <!-- Section Subheader ("In Progress" + Down Arrow + Dots) -->
            <div class="flex items-center justify-between pt-1">
              <span id="ios-queue-status-label" class="text-sm font-extrabold text-zinc-900">In Progress</span>
              <div class="flex items-center gap-1.5">
                <span class="w-7 h-7 rounded-full bg-white flex items-center justify-center text-zinc-700 shadow-xs">
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 13.5L12 21m0 0l-7.5-7.5M12 21V3"/></svg>
                </span>
                <span class="px-2.5 py-1 rounded-full bg-white text-[11px] font-mono font-bold text-zinc-700 shadow-xs tabular-nums" id="ios-queue-count-badge">
                  14 items
                </span>
              </div>
            </div>

            <!-- Upload Progress Cards (Exact Match to "Maya Jinna Sohana 80%" Rows) -->
            <div id="ios-upload-queue-list" class="space-y-2.5">
              <!-- Populated by JS -->
            </div>
          </div>

        </div>

        <!-- =================================================================== -->
        <!-- SIGNATURE FLOATING BLACK PILL BOTTOM NAV BAR (Matches Reference)    -->
        <!-- =================================================================== -->
        <div class="absolute bottom-5 inset-x-6 z-30">
          <nav aria-label="iPhone Navigation" class="bg-pillnav rounded-full p-2 flex items-center justify-between shadow-pill">
            <!-- Tab 1: Home -->
            <button type="button" onclick="switchIosTab('home')" id="ios-nav-home"
              aria-label="Home"
              class="w-10 h-10 rounded-full bg-white text-zinc-900 flex items-center justify-center transition-all">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" />
              </svg>
            </button>

            <!-- Tab 2: Photos Grid -->
            <button type="button" onclick="switchIosTab('photos')" id="ios-nav-photos"
              aria-label="Selective Photos"
              class="w-10 h-10 rounded-full text-white/70 hover:text-white flex items-center justify-center transition-all">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" />
              </svg>
            </button>

            <!-- CENTER ELECTRIC BLUE 1-TAP SYNC TRIGGER BUTTON -->
            <button type="button" onclick="triggerOneTapSync()" id="ios-nav-center-plus"
              title="1-Tap Catch-Up Sync"
              class="w-11 h-11 rounded-full bg-electric hover:bg-blue-600 active:scale-90 text-white flex items-center justify-center shadow-md transition-all">
              <svg id="ios-center-btn-icon" class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
              </svg>
            </button>

            <!-- Tab 3: Upload Queue -->
            <button type="button" onclick="switchIosTab('queue')" id="ios-nav-queue"
              aria-label="Upload Progress"
              class="w-10 h-10 rounded-full text-white/70 hover:text-white flex items-center justify-center transition-all relative">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
              </svg>
            </button>

            <!-- Tab 4: Switch to Samsung Receiver Focus -->
            <button type="button" onclick="switchSamsungTab('settings')" id="ios-nav-info"
              aria-label="Watermark Info"
              class="w-10 h-10 rounded-full text-white/70 hover:text-white flex items-center justify-center transition-all">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z" />
              </svg>
            </button>
          </nav>
        </div>

      </div>
    </section>

    <!-- ======================================================================= -->
    <!-- DEVICE 2: SAMSUNG GALAXY S24 ULTRA (ANDROID APK RECEIVER SERVER)        -->
    <!-- ======================================================================= -->
    <section id="frame-samsung" aria-label="Samsung S24 Ultra Android APK Server" class="w-full max-w-[380px] flex flex-col items-center">
      <!-- Subtle Device Label Above Phone -->
      <div class="device-label mb-3 flex items-center gap-2">
        <span class="px-3 py-1 rounded-full bg-pillnav text-white text-[11px] font-bold tracking-wide uppercase shadow-xs">
          Android APK &bull; Receiver Server
        </span>
        <span class="text-xs font-medium text-zinc-600">Samsung S24 Ultra</span>
      </div>

      <!-- Samsung S24 Ultra Hardware Shell (Slightly sharper corners + punch-hole camera) -->
      <div class="device-shell w-full h-[790px] bg-appbg rounded-[38px] shadow-phone relative overflow-hidden flex flex-col justify-between select-none">
        
        <!-- Top Android Status Bar + Punch Hole Camera -->
        <div class="ios-hardware-bar px-6 pt-3.5 pb-2 flex items-center justify-between text-xs font-bold text-zinc-900 z-20">
          <span class="tabular-nums">11:30</span>
          <!-- S24 Punch-Hole Camera -->
          <div class="w-3.5 h-3.5 rounded-full bg-pillnav flex items-center justify-center">
            <div class="w-1.5 h-1.5 rounded-full bg-zinc-700"></div>
          </div>
          <div class="flex items-center gap-1.5">
            <span class="text-[10px] font-mono font-bold px-1.5 py-0.2 bg-zinc-200 rounded text-zinc-700">VPN</span>
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0"/></svg>
            <span class="text-[11px] font-mono tabular-nums">94%</span>
          </div>
        </div>

        <!-- SCROLLABLE VIEWPORT CONTAINER FOR SAMSUNG APK SCREENS -->
        <div class="flex-1 overflow-y-auto no-scrollbar px-5 pt-1 pb-24 relative">

          <!-- ================================================================= -->
          <!-- SAMSUNG SCREEN 1: FOLDERS & SERVER HOME (Matches Center Mint UI)  -->
          <!-- ================================================================= -->
          <div id="sam-screen-home" class="space-y-4">
            
            <!-- Header Row ("Dropbox" + Upload & Check Circle Buttons in Center Reference) -->
            <div class="flex items-center justify-between pt-1">
              <div>
                <h2 class="text-[24px] font-extrabold tracking-tight text-zinc-900 leading-none">DropServer</h2>
                <p class="text-[11px] font-medium text-zinc-500 mt-1 tabular-nums" id="sam-subtitle-ip">
                  Tailscale &bull; 100.76.50.39:8080
                </p>
              </div>
              <div class="flex items-center gap-2">
                <button type="button" onclick="toggleServerOnline()" id="sam-server-toggle-btn"
                  title="Toggle HTTP Receiver Daemon"
                  class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-emerald-600 hover:bg-zinc-50 transition-colors">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M5.636 5.636a9 9 0 1012.728 0M12 3v9" />
                  </svg>
                </button>
                <button type="button" onclick="switchSamsungTab('settings')"
                  title="Server High-Watermark Ledger"
                  class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800 hover:bg-zinc-50 transition-colors">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </button>
              </div>
            </div>

            <!-- Endpoint Pill Bar -->
            <div class="bg-white rounded-full px-4 py-3 flex items-center justify-between shadow-soft">
              <div class="flex items-center gap-2 min-w-0">
                <span id="sam-daemon-dot" class="w-2.5 h-2.5 rounded-full bg-emerald-500 flex-shrink-0"></span>
                <span id="sam-endpoint-text" class="text-xs font-mono text-zinc-600 truncate">
                  GET /d/tk_8821/sync/status
                </span>
              </div>
              <span id="sam-http-badge" class="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800">
                200 OK
              </span>
            </div>

            <!-- 3 Pastel Quick Pills (Matches "Upload / Folder / Scan" Row in Reference) -->
            <div class="grid grid-cols-3 gap-2">
              <button type="button" onclick="switchSamsungTab('stream')"
                class="py-2.5 px-2.5 rounded-full bg-[#DFF2E6] text-zinc-900 text-[11px] font-bold flex items-center justify-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-emerald-600"></span>
                <span id="sam-pill-count" class="tabular-nums">4,806 In</span>
              </button>
              <button type="button" onclick="switchSamsungTab('settings')"
                class="py-2.5 px-2.5 rounded-full bg-[#FADCE6] text-zinc-900 text-[11px] font-bold flex items-center justify-center gap-1.5">
                <span class="tabular-nums" id="sam-pill-free">142 GB Free</span>
              </button>
              <button type="button" onclick="switchSamsungTab('settings')"
                class="py-2.5 px-2.5 rounded-full bg-[#DCEBFF] text-zinc-900 text-[11px] font-bold flex items-center justify-center gap-1.5">
                <span>QR Pair</span>
              </button>
            </div>

            <!-- MINT GREEN FOLDER CONTAINER (Exact Match to Center Screen in Reference) -->
            <div class="bg-mint-card rounded-[28px] p-4 shadow-soft space-y-2.5">
              <div class="flex items-center justify-between px-1 pb-1">
                <span class="text-xs font-extrabold text-zinc-900">Samsung Storage Folders &uarr;</span>
                <span class="w-7 h-7 rounded-full bg-white/80 flex items-center justify-center text-zinc-700">
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5"/></svg>
                </span>
              </div>

              <!-- White Inner Row 1: Camera Roll Sync -->
              <div onclick="switchSamsungTab('stream')" class="bg-white rounded-2xl p-3 flex items-center justify-between shadow-xs cursor-pointer hover:scale-[1.01] transition-transform">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-[#DFF2E6] text-emerald-700 flex items-center justify-center">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5z"/></svg>
                  </div>
                  <div>
                    <div class="text-xs font-extrabold text-zinc-900">DCIM / iPhone_17_Pro</div>
                    <div id="sam-folder-photos-meta" class="text-[11px] font-medium text-zinc-500 tabular-nums">60.5 GB &bull; 4,510 HEIC</div>
                  </div>
                </div>
                <span class="text-zinc-400 font-bold text-sm px-1">&bull;&bull;&bull;</span>
              </div>

              <!-- White Inner Row 2: 4K Videos -->
              <div onclick="switchSamsungTab('stream')" class="bg-white rounded-2xl p-3 flex items-center justify-between shadow-xs cursor-pointer hover:scale-[1.01] transition-transform">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-[#DCEBFF] text-electric flex items-center justify-center">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 10.5l4.72-4.72a.75.75 0 011.28.53v11.38a.75.75 0 01-1.28.53l-4.72-4.72M4.5 18.75h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25h-9A2.25 2.25 0 002.25 7.5v9a2.25 2.25 0 002.25 2.25z"/></svg>
                  </div>
                  <div>
                    <div class="text-xs font-extrabold text-zinc-900">Movies / iPhone_4K60</div>
                    <div id="sam-folder-videos-meta" class="text-[11px] font-medium text-zinc-500 tabular-nums">10.5 GB &bull; 214 MOV</div>
                  </div>
                </div>
                <span class="text-zinc-400 font-bold text-sm px-1">&bull;&bull;&bull;</span>
              </div>

              <!-- White Inner Row 3: ProRAW Captures -->
              <div onclick="switchSamsungTab('stream')" class="bg-white rounded-2xl p-3 flex items-center justify-between shadow-xs cursor-pointer hover:scale-[1.01] transition-transform">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-[#FFF1B8] text-amber-700 flex items-center justify-center font-mono text-xs font-extrabold">
                    DNG
                  </div>
                  <div>
                    <div class="text-xs font-extrabold text-zinc-900">DCIM / ProRAW_Lossless</div>
                    <div id="sam-folder-raw-meta" class="text-[11px] font-medium text-zinc-500 tabular-nums">8.4 GB &bull; 82 DNG</div>
                  </div>
                </div>
                <span class="text-zinc-400 font-bold text-sm px-1">&bull;&bull;&bull;</span>
              </div>

              <!-- White Inner Row 4: High-Watermark SQLite/JSON Ledger -->
              <div onclick="switchSamsungTab('settings')" class="bg-white rounded-2xl p-3 flex items-center justify-between shadow-xs cursor-pointer hover:scale-[1.01] transition-transform">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-[#FADCE6] text-rose-600 flex items-center justify-center">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375"/></svg>
                  </div>
                  <div>
                    <div class="text-xs font-extrabold text-zinc-900">sync_ledger.sqlite</div>
                    <div id="sam-folder-ledger-meta" class="text-[11px] font-mono text-zinc-500 tabular-nums">Watermark: Nov 8, 14:32</div>
                  </div>
                </div>
                <span class="text-zinc-400 font-bold text-sm px-1">&bull;&bull;&bull;</span>
              </div>
            </div>

          </div>

          <!-- ================================================================= -->
          <!-- SAMSUNG SCREEN 2: INCOMING STREAM (Real-time Receiver Feed)       -->
          <!-- ================================================================= -->
          <div id="sam-screen-stream" class="hidden space-y-4">
            <div class="flex items-center justify-between pt-1">
              <button type="button" onclick="switchSamsungTab('home')"
                class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800 hover:bg-zinc-100">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18"/></svg>
              </button>
              <h2 class="text-base font-extrabold text-zinc-900">Incoming Stream</h2>
              <span id="sam-stream-live-pill" class="px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-800 text-[10px] font-extrabold uppercase">
                Listening
              </span>
            </div>

            <!-- High-Watermark Banner Card -->
            <div class="bg-white rounded-[24px] p-4 shadow-soft flex items-center justify-between">
              <div>
                <div class="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">High-Watermark Timestamp</div>
                <div id="sam-stream-watermark" class="text-sm font-mono font-bold text-zinc-900 mt-0.5 tabular-nums">
                  2026-11-08 14:32:10
                </div>
              </div>
              <div class="text-right">
                <div class="text-[11px] font-semibold text-zinc-400">Total Stored</div>
                <div id="sam-stream-total" class="text-sm font-extrabold text-electric tabular-nums">4,806 items</div>
              </div>
            </div>

            <!-- Incoming File Feed Rows -->
            <div class="flex items-center justify-between pt-1">
              <span class="text-xs font-extrabold text-zinc-900">Recently Written to Disk</span>
              <span class="text-[11px] font-mono text-zinc-500">POST /upload</span>
            </div>

            <div id="sam-incoming-list" class="space-y-2.5">
              <!-- Populated by JS as files arrive from iPhone -->
            </div>
          </div>

          <!-- ================================================================= -->
          <!-- SAMSUNG SCREEN 3: SERVER PLAN & WATERMARK API (Top-Right Ref)     -->
          <!-- ================================================================= -->
          <div id="sam-screen-settings" class="hidden space-y-4">
            <div class="flex items-center justify-between pt-1">
              <button type="button" onclick="switchSamsungTab('home')"
                class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800 hover:bg-zinc-100">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18"/></svg>
              </button>
              <h2 class="text-base font-extrabold text-zinc-900">Server Node</h2>
              <div class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125"/></svg>
              </div>
            </div>

            <!-- "Your Plan / Dropbox Basic Free" Equivalent Storage Card -->
            <div class="bg-white rounded-[26px] p-4 shadow-soft space-y-3">
              <div class="flex items-start gap-3">
                <div class="w-11 h-11 rounded-2xl bg-blue-50 text-electric flex items-center justify-center flex-shrink-0">
                  <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2L4.5 6.5 12 11l7.5-4.5L12 2zm-7.5 9L12 15.5 19.5 11 12 6.5 4.5 11zm7.5 6.5l-7.5-4.5v3L12 20.5l7.5-4.5v-3L12 17.5z"/></svg>
                </div>
                <div class="flex-1">
                  <div class="text-[11px] font-medium text-zinc-400">Samsung Internal UFS 4.0</div>
                  <div class="flex items-center gap-2">
                    <span class="text-sm font-extrabold text-zinc-900">256 GB Storage</span>
                    <span id="sam-free-pill" class="px-2 py-0.5 rounded-full bg-electric text-white text-[10px] font-bold tabular-nums">142.4 GB Free</span>
                  </div>
                  <p class="text-[11px] text-zinc-500 mt-0.5">Zero cloud fees &bull; Direct local / Tailscale transfer</p>
                </div>
              </div>

              <!-- White Pill Button with Black Right Arrow (Matches "Manage Your Plan ->") -->
              <button type="button" onclick="triggerOneTapSync()"
                class="w-full bg-appbg hover:bg-zinc-200/70 rounded-full pl-4 pr-1.5 py-1.5 flex items-center justify-between transition-colors">
                <span class="text-xs font-bold text-zinc-800">Trigger Catch-Up From iPhone</span>
                <span class="w-7 h-7 rounded-full bg-pillnav text-white flex items-center justify-center">
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"/></svg>
                </span>
              </button>
            </div>

            <!-- 3 Stacked Settings Rows (Matches "Camera Uploads / Link your desktop / Recover") -->
            <div class="space-y-2.5">
              <div class="bg-white rounded-2xl p-3 flex items-center justify-between shadow-soft">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-[#DCEBFF] text-electric flex items-center justify-center">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6.827 6.175A2.31 2.31 0 015.186 7.23c-.38.054-.757.112-1.134.175C2.999 7.58 2.25 8.507 2.25 9.574V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9.574c0-1.067-.75-1.994-1.802-2.169a47.865 47.865 0 00-1.134-.175 2.31 2.31 0 01-1.64-1.055l-.822-1.316a2.192 2.192 0 00-1.736-1.039 48.774 48.774 0 00-5.232 0 2.192 2.192 0 00-1.736 1.039l-.821 1.316z"/></svg>
                  </div>
                  <div>
                    <div class="text-xs font-extrabold text-zinc-900">High-Watermark Auto Resume</div>
                    <div class="text-[11px] text-zinc-500">Returns latest_captured_at timestamp</div>
                  </div>
                </div>
                <span class="text-zinc-500 pr-1">&rarr;</span>
              </div>

              <div class="bg-white rounded-2xl p-3 flex items-center justify-between shadow-soft">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-[#DFF2E6] text-emerald-700 flex items-center justify-center">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244"/></svg>
                  </div>
                  <div>
                    <div class="text-xs font-extrabold text-zinc-900">iOS Action Button Shortcut</div>
                    <div class="text-[11px] text-zinc-500">Bound to token /d/tk_8821/upload</div>
                  </div>
                </div>
                <span class="text-zinc-500 pr-1">&rarr;</span>
              </div>

              <div class="bg-white rounded-2xl p-3 flex items-center justify-between shadow-soft">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-xl bg-[#FFF1B8] text-amber-700 flex items-center justify-center">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/></svg>
                  </div>
                  <div>
                    <div class="text-xs font-extrabold text-zinc-900">SHA-256 Deduplication Guard</div>
                    <div class="text-[11px] text-zinc-500">Skips identical files in Selective Mode</div>
                  </div>
                </div>
                <span class="text-zinc-500 pr-1">&rarr;</span>
              </div>
            </div>

            <!-- Live JSON Response Preview -->
            <div class="bg-pillnav rounded-2xl p-3 text-[10px] font-mono text-zinc-300 space-y-1">
              <div class="text-emerald-400 font-bold">// GET /d/tk_8821/sync/status</div>
              <div id="sam-json-watermark">"latest_captured_at": "2026-11-08 14:32:10",</div>
              <div id="sam-json-count">"backed_up_assets": 4806,</div>
              <div id="sam-json-free">"free_space_gb": 142.4</div>
            </div>
          </div>

        </div>

        <!-- =================================================================== -->
        <!-- SAMSUNG FLOATING BLACK PILL BOTTOM NAV BAR                          -->
        <!-- =================================================================== -->
        <div class="absolute bottom-5 inset-x-6 z-30">
          <nav aria-label="Samsung APK Navigation" class="bg-pillnav rounded-full p-2 flex items-center justify-between shadow-pill">
            <!-- Tab 1: Folders Home -->
            <button type="button" onclick="switchSamsungTab('home')" id="sam-nav-home"
              aria-label="Server Home"
              class="w-10 h-10 rounded-full bg-white text-zinc-900 flex items-center justify-center transition-all">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
              </svg>
            </button>

            <!-- Tab 2: Live Stream -->
            <button type="button" onclick="switchSamsungTab('stream')" id="sam-nav-stream"
              aria-label="Incoming Stream"
              class="w-10 h-10 rounded-full text-white/70 hover:text-white flex items-center justify-center transition-all">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
              </svg>
            </button>

            <!-- Center Electric Blue Server Pulse / Trigger Button -->
            <button type="button" onclick="switchSamsungTab('stream')"
              title="Inspect Incoming Stream"
              class="w-11 h-11 rounded-full bg-electric hover:bg-blue-600 active:scale-90 text-white flex items-center justify-center shadow-md transition-all">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.3" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </button>

            <!-- Tab 3: Settings / Watermark API -->
            <button type="button" onclick="switchSamsungTab('settings')" id="sam-nav-settings"
              aria-label="Server Settings"
              class="w-10 h-10 rounded-full text-white/70 hover:text-white flex items-center justify-center transition-all">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M10.343 3.94c.09-.542.56-.94 1.11-.94h1.093c.55 0 1.02.398 1.11.94l.149.894c.07.424.384.764.78.93.398.164.855.142 1.205-.108l.737-.527a1.125 1.125 0 011.45.12l.773.774c.39.389.44 1.002.12 1.45l-.527.737c-.25.35-.272.806-.107 1.204.165.397.505.71.93.78l.893.15c.543.09.94.56.94 1.109v1.094c0 .55-.397 1.02-.94 1.11l-.893.149c-.425.07-.765.383-.93.78-.165.398-.143.854.107 1.204l.527.738c.32.447.269 1.06-.12 1.45l-.774.773a1.125 1.125 0 01-1.449.12l-.738-.527c-.35-.25-.806-.272-1.203-.107-.397.165-.71.505-.781.929l-.149.894c-.09.542-.56.94-1.11.94h-1.094c-.55 0-1.019-.398-1.11-.94l-.148-.894c-.071-.424-.384-.764-.781-.93-.398-.164-.854-.142-1.204.108l-.738.527c-.447.32-1.06.269-1.45-.12l-.773-.774a1.125 1.125 0 01-.12-1.45l.527-.737c.25-.35.273-.806.108-1.204-.165-.397-.505-.71-.93-.78l-.894-.15c-.542-.09-.94-.56-.94-1.109v-1.094c0-.55.398-1.02.94-1.11l.894-.149c.424-.07.765-.383.93-.78.165-.398.143-.854-.108-1.204l-.526-.738a1.125 1.125 0 01.12-1.45l.773-.773a1.125 1.125 0 011.45-.12l.737.527c.35.25.807.272 1.204.107.397-.165.71-.505.78-.929l.15-.894z" />
              </svg>
            </button>

            <!-- Tab 4: Power Toggle -->
            <button type="button" onclick="toggleServerOnline()" id="sam-nav-power"
              aria-label="Toggle Server"
              class="w-10 h-10 rounded-full text-emerald-400 hover:text-emerald-300 flex items-center justify-center transition-all">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M5.636 5.636a9 9 0 1012.728 0M12 3v9" />
              </svg>
            </button>
          </nav>
        </div>

      </div>
    </section>

  </main>

  <!-- ========================================================================= -->
  <!-- DUAL-DEVICE REALTIME SYNC ENGINE                                          -->
  <!-- ========================================================================= -->
  <script>
    const BASE = "{{BASE}}";
    const TOKEN = "{{TOKEN}}";
    function randomHex(len) {
      const arr = new Uint8Array(Math.ceil(len / 2));
      crypto.getRandomValues(arr);
      return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, len);
    }
    const BATCH = randomHex(12);

    function pickRealPhotos() {
      const picker = document.getElementById('real-file-picker');
      if (picker) picker.click();
    }

    const INITIAL_ITEMS = [
      // 4 Already Synced Items (Captured <= 2026-11-08 14:32:10)
      { id: 'm1', title: 'Summer Memories', name: 'IMG_4803.HEIC', category: 'photo', sizeMB: 3.2, dateLabel: 'Nov 8 • 13:50', capturedAt: '2026-11-08 13:50:12', synced: true, selected: false, progress: 100, url: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?auto=format&fit=crop&w=400&q=80' },
      { id: 'm2', title: 'Paris Vacation',  name: 'IMG_4804.HEIC', category: 'photo', sizeMB: 4.1, dateLabel: 'Nov 8 • 14:12', capturedAt: '2026-11-08 14:12:05', synced: true, selected: false, progress: 100, url: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?auto=format&fit=crop&w=400&q=80' },
      { id: 'm3', title: 'Trip to Samui',   name: 'IMG_4805.DNG',  category: 'raw',   sizeMB: 18.4, dateLabel: 'Nov 8 • 14:28', capturedAt: '2026-11-08 14:28:44', synced: true, selected: false, progress: 100, url: 'https://images.unsplash.com/photo-1506744038136-46273834b3fb?auto=format&fit=crop&w=400&q=80' },
      { id: 'm4', title: 'Nature of Cubes', name: 'IMG_4806.HEIC', category: 'photo', sizeMB: 2.8, dateLabel: 'Nov 8 • 14:32', capturedAt: '2026-11-08 14:32:10', synced: true, selected: false, progress: 100, url: 'https://images.unsplash.com/photo-1518709268805-4e9042af9f23?auto=format&fit=crop&w=400&q=80' },

      // 14 Unsynced Delta Items (Captured > 2026-11-08 14:32:10)
      { id: 'm5',  title: 'Golden Coastline', name: 'IMG_4807.HEIC', category: 'photo', sizeMB: 3.4, dateLabel: 'Nov 8 • 15:04', capturedAt: '2026-11-08 15:04:19', synced: false, selected: true,  progress: 0, url: 'https://images.unsplash.com/photo-1501785888041-af3ef285b470?auto=format&fit=crop&w=400&q=80' },
      { id: 'm6',  title: 'Alpine Ridge',     name: 'IMG_4808.HEIC', category: 'photo', sizeMB: 3.9, dateLabel: 'Nov 8 • 15:18', capturedAt: '2026-11-08 15:18:02', synced: false, selected: true,  progress: 0, url: 'https://images.unsplash.com/photo-1469474968028-56623f02e42e?auto=format&fit=crop&w=400&q=80' },
      { id: 'm7',  title: 'Sunset Reel 4K',   name: 'MOV_4809.MOV',  category: 'video', sizeMB: 14.2, dateLabel: 'Nov 8 • 16:02', capturedAt: '2026-11-08 16:02:51', synced: false, selected: true,  progress: 0, url: 'https://images.unsplash.com/photo-1472214103451-9374bd1c798e?auto=format&fit=crop&w=400&q=80' },
      { id: 'm8',  title: 'Starlight Peak',   name: 'IMG_4810.HEIC', category: 'photo', sizeMB: 2.7, dateLabel: 'Nov 8 • 16:40', capturedAt: '2026-11-08 16:40:11', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1519681393784-d120267933ba?auto=format&fit=crop&w=400&q=80' },
      { id: 'm9',  title: 'Forest ProRAW',    name: 'RAW_4811.DNG',  category: 'raw',   sizeMB: 12.8, dateLabel: 'Nov 8 • 17:15', capturedAt: '2026-11-08 17:15:33', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1441974231531-c6227db76b6e?auto=format&fit=crop&w=400&q=80' },
      { id: 'm10', title: 'Desert Highway',   name: 'IMG_4812.HEIC', category: 'photo', sizeMB: 3.1, dateLabel: 'Nov 8 • 18:05', capturedAt: '2026-11-08 18:05:49', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?auto=format&fit=crop&w=400&q=80' },
      { id: 'm11', title: 'Misty Valley',     name: 'IMG_4813.HEIC', category: 'photo', sizeMB: 2.9, dateLabel: 'Nov 8 • 18:22', capturedAt: '2026-11-08 18:22:10', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1493246507139-91e8fad9978e?auto=format&fit=crop&w=400&q=80' },
      { id: 'm12', title: 'Redwood Trail',    name: 'IMG_4814.HEIC', category: 'photo', sizeMB: 3.6, dateLabel: 'Nov 8 • 19:11', capturedAt: '2026-11-08 19:11:04', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1511497584788-876760111969?auto=format&fit=crop&w=400&q=80' },
      { id: 'm13', title: 'Night Hyperlapse', name: 'MOV_4815.MOV',  category: 'video', sizeMB: 8.4, dateLabel: 'Nov 8 • 20:01', capturedAt: '2026-11-08 20:01:38', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1465146344425-f00d5f5c8f07?auto=format&fit=crop&w=400&q=80' },
      { id: 'm14', title: 'Cascade Falls',    name: 'IMG_4816.HEIC', category: 'photo', sizeMB: 2.5, dateLabel: 'Nov 9 • 07:45', capturedAt: '2026-11-09 07:45:12', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1433086966358-54859d0ed716?auto=format&fit=crop&w=400&q=80' },
      { id: 'm15', title: 'Morning Pier',     name: 'IMG_4817.HEIC', category: 'photo', sizeMB: 3.0, dateLabel: 'Nov 9 • 08:12', capturedAt: '2026-11-09 08:12:29', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1475924156734-496f6cac6ec1?auto=format&fit=crop&w=400&q=80' },
      { id: 'm16', title: 'Sunlit Canopy',    name: 'RAW_4818.DNG',  category: 'raw',   sizeMB: 2.4, dateLabel: 'Nov 9 • 08:30', capturedAt: '2026-11-09 08:30:00', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1502082553048-f009c37129b9?auto=format&fit=crop&w=400&q=80' },
      { id: 'm17', title: 'Autumn Path',      name: 'IMG_4819.HEIC', category: 'photo', sizeMB: 2.8, dateLabel: 'Nov 9 • 09:05', capturedAt: '2026-11-09 09:05:17', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1447752875215-b2761acb3c5d?auto=format&fit=crop&w=400&q=80' },
      { id: 'm18', title: 'Mirror Lake',      name: 'IMG_4820.HEIC', category: 'photo', sizeMB: 2.7, dateLabel: 'Nov 9 • 09:18', capturedAt: '2026-11-09 09:18:42', synced: false, selected: false, progress: 0, url: 'https://images.unsplash.com/photo-1426604966848-d7adac402bff?auto=format&fit=crop&w=400&q=80' }
    ];

    const BASE_SYNCED_OFFSET = 4802;
    let activeXhr = null;

    const app = {
      items: JSON.parse(JSON.stringify(INITIAL_ITEMS)),
      iosTab: 'home',       // 'home' | 'photos' | 'queue'
      samTab: 'home',       // 'home' | 'stream' | 'settings'
      photoFilter: 'unsynced', // 'unsynced' | 'all'
      serverOnline: true,
      isSyncing: false,
      isPaused: false,
      showAllQueue: false,
      syncInterval: null,
      freeGB: 142.4,
      photosGB: 60.5,
      videosGB: 10.5,
      rawGB: 8.4,
      nextCaptureId: 4821
    };

    function getDeltaStats() {
      const unsynced = app.items.filter(i => !i.synced);
      const synced = app.items.filter(i => i.synced);
      const newPhotos = unsynced.filter(i => i.category === 'photo').length;
      const newVideos = unsynced.filter(i => i.category === 'video').length;
      const newRaw = unsynced.filter(i => i.category === 'raw').length;
      const totalSynced = BASE_SYNCED_OFFSET + synced.length;
      const deltaMB = unsynced.reduce((sum, i) => sum + i.sizeMB, 0);
      const latestSynced = synced[synced.length - 1];
      const watermark = latestSynced ? latestSynced.capturedAt : '2026-11-08 14:32:10';

      return {
        unsynced,
        synced,
        unsyncedCount: unsynced.length,
        newPhotos,
        newVideos,
        newRaw,
        totalSynced,
        deltaMB: Number(deltaMB.toFixed(1)),
        watermark
      };
    }

    // --- Viewport Switcher (Side-by-Side vs Single Phone) ---
    function setViewportMode(mode) {
      const iphone = document.getElementById('frame-iphone');
      const samsung = document.getElementById('frame-samsung');
      const mIphone = document.getElementById('m-btn-iphone');
      const mSamsung = document.getElementById('m-btn-samsung');
      const modes = ['both', 'iphone', 'samsung'];

      modes.forEach(m => {
        const btn = document.getElementById(`view-btn-${m}`);
        if (btn) {
          if (m === mode) {
            btn.className = 'px-3.5 py-1.5 rounded-full text-xs font-bold bg-pillnav text-white transition-all';
          } else {
            btn.className = 'px-3.5 py-1.5 rounded-full text-xs font-semibold text-zinc-600 hover:text-zinc-900 transition-all';
          }
        }
      });

      if (mode === 'both') {
        if (iphone) iphone.classList.remove('hidden');
        if (samsung) samsung.classList.remove('hidden');
        if (mIphone) mIphone.className = 'px-3 py-1 rounded-full text-[11px] font-bold bg-white text-zinc-900 shadow-xs transition-all';
        if (mSamsung) mSamsung.className = 'px-3 py-1 rounded-full text-[11px] font-bold text-zinc-500 transition-all';
      } else if (mode === 'iphone') {
        if (iphone) iphone.classList.remove('hidden');
        if (samsung) samsung.classList.add('hidden');
        if (mIphone) mIphone.className = 'px-3 py-1 rounded-full text-[11px] font-bold bg-white text-zinc-900 shadow-xs transition-all';
        if (mSamsung) mSamsung.className = 'px-3 py-1 rounded-full text-[11px] font-bold text-zinc-500 transition-all';
      } else {
        if (iphone) iphone.classList.add('hidden');
        if (samsung) samsung.classList.remove('hidden');
        if (mIphone) mIphone.className = 'px-3 py-1 rounded-full text-[11px] font-bold text-zinc-500 transition-all';
        if (mSamsung) mSamsung.className = 'px-3 py-1 rounded-full text-[11px] font-bold bg-white text-zinc-900 shadow-xs transition-all';
      }
    }

    // --- Navigation Tabs: iPhone PWA ---
    function switchIosTab(tab) {
      app.iosTab = tab;
      ['home', 'photos', 'queue'].forEach(t => {
        const screen = document.getElementById(`ios-screen-${t}`);
        const navBtn = document.getElementById(`ios-nav-${t}`);
        if (t === tab) {
          screen.classList.remove('hidden');
          navBtn.className = 'w-10 h-10 rounded-full bg-white text-zinc-900 flex items-center justify-center transition-all shadow-xs';
        } else {
          screen.classList.add('hidden');
          navBtn.className = 'w-10 h-10 rounded-full text-white/70 hover:text-white flex items-center justify-center transition-all';
        }
      });
      renderAll();
    }

    // --- Navigation Tabs: Samsung APK ---
    function switchSamsungTab(tab) {
      app.samTab = tab;
      ['home', 'stream', 'settings'].forEach(t => {
        const screen = document.getElementById(`sam-screen-${t}`);
        const navBtn = document.getElementById(`sam-nav-${t}`);
        if (t === tab) {
          screen.classList.remove('hidden');
          navBtn.className = 'w-10 h-10 rounded-full bg-white text-zinc-900 flex items-center justify-center transition-all shadow-xs';
        } else {
          screen.classList.add('hidden');
          navBtn.className = 'w-10 h-10 rounded-full text-white/70 hover:text-white flex items-center justify-center transition-all';
        }
      });
      renderAll();
    }

    function openSyncedFilter() {
      app.photoFilter = 'all';
      switchIosTab('photos');
    }

    function setPhotoFilter(filter) {
      app.photoFilter = filter;
      renderIosPhotosScreen();
    }

    function togglePhotoSelect(id) {
      const item = app.items.find(i => i.id === id);
      if (!item || item.synced) return; // Automatically skip already synced items
      item.selected = !item.selected;
      renderIosPhotosScreen();
    }

    function toggleSelectAllUnsynced() {
      const unsynced = app.items.filter(i => !i.synced);
      const allSelected = unsynced.length > 0 && unsynced.every(i => i.selected);
      unsynced.forEach(i => { i.selected = !allSelected; });
      renderIosPhotosScreen();
    }

    // --- Toggle Samsung Server Daemon Online/Offline ---
    function toggleServerOnline() {
      app.serverOnline = !app.serverOnline;
      if (!app.serverOnline && app.isSyncing) {
        stopSyncTimer();
      }
      renderAll();
    }

    // --- Duplicate & Resume Diff Checker ---
    async function checkServerDuplicates(itemsToCheck = null) {
      const pool = itemsToCheck || app.items.filter(i => !i.synced);
      if (!pool.length) return;

      const candidateList = pool.map(i => ({
        name: i.name,
        size: i.file ? i.file.size : Math.round(i.sizeMB * 1024 * 1024)
      }));

      try {
        const res = await fetch(`${BASE}/sync/diff`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ items: candidateList })
        });
        if (res.ok) {
          const diff = await res.json();
          const already = new Set(diff.already_synced || []);
          if (already.size > 0) {
            pool.forEach(i => {
              if (already.has(i.name)) {
                i.synced = true;
                i.progress = 100;
                i.selected = false;
              }
            });
            renderAll();
          }
        }
      } catch (_) {}
    }

    // --- Play / Pause Controls ---
    function pauseTransfer() {
      app.isPaused = true;
      app.isSyncing = false;
      if (activeXhr) {
        try { activeXhr.abort(); } catch (_) {}
        activeXhr = null;
      }
      renderAll();
    }

    function resumeTransfer() {
      app.isPaused = false;
      app.isSyncing = true;
      startRealtimeSyncLoop();
    }

    function togglePlayPause() {
      if (app.isSyncing) {
        pauseTransfer();
      } else {
        resumeTransfer();
      }
    }

    // --- Trigger 1-Tap Catch-Up Sync Across Both Phones ---
    function triggerOneTapSync() {
      if (!app.serverOnline) {
        toggleServerOnline();
      }

      const stats = getDeltaStats();
      if (stats.unsyncedCount === 0) {
        pickRealPhotos();
        return;
      }

      if (app.isSyncing) {
        pauseTransfer();
        return;
      }

      switchIosTab('queue');
      resumeTransfer();
    }

    // --- Sync Only Selected Photos (Mode B) ---
    function syncSelectedPhotos() {
      const selected = app.items.filter(i => !i.synced && i.selected);
      if (selected.length === 0) return;
      switchIosTab('queue');
      switchSamsungTab('stream');
      app.isPaused = false;
      app.isSyncing = true;
      startRealtimeSyncLoop( true );
    }

    function handleFilesSelected(files) {
      if (!files || !files.length) return;

      // When picking real files, remove sample demo items
      if (app.items.some(i => !i.file)) {
        app.items = app.items.filter(i => i.file);
      }

      const now = new Date();
      const pad = n => String(n).padStart(2, '0');
      const timeStr = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
      const dateLabel = `Today • ${pad(now.getHours())}:${pad(now.getMinutes())}`;

      const added = [];
      files.forEach((f, idx) => {
        const isRaw = f.name.toLowerCase().endsWith('.dng') || f.name.toLowerCase().endsWith('.raw');
        const isVideo = f.type.startsWith('video/') || f.name.toLowerCase().endsWith('.mov') || f.name.toLowerCase().endsWith('.mp4');
        const cat = isRaw ? 'raw' : (isVideo ? 'video' : 'photo');
        const sizeMB = Number((f.size / (1024 * 1024)).toFixed(1));
        const isImg = f.type.startsWith('image/');
        // Lazy preview URLs: allocate only for first 30 images to keep memory small on 500+ batches
        const url = (isImg && idx < 30) ? URL.createObjectURL(f) : '';

        const itemObj = {
          id: 'rf_' + Date.now() + '_' + idx,
          file: f,
          title: f.name.replace(/\\.[^/.]+$/, ""),
          name: f.name,
          category: cat,
          sizeMB: sizeMB || 0.1,
          dateLabel: dateLabel,
          capturedAt: `${now.getFullYear()}-${pad(now.getMonth()+1)}-${pad(now.getDate())} ${timeStr}`,
          synced: false,
          selected: true,
          progress: 0,
          url: url,
          err: false,
          errMessage: ''
        };
        app.items.push(itemObj);
        added.push(itemObj);
      });

      switchIosTab('queue');
      renderAll();

      // Automatically query server sync diff to skip any files already backed up
      checkServerDuplicates(added);
    }

    // --- Real File Picker Listener ---
    document.addEventListener('DOMContentLoaded', () => {
      const picker = document.getElementById('real-file-picker');
      if (picker) {
        picker.addEventListener('change', (e) => {
          handleFilesSelected(Array.from(picker.files || []));
          picker.value = '';
        });
      }

      window.addEventListener('dragover', (e) => { e.preventDefault(); });
      window.addEventListener('drop', (e) => {
        e.preventDefault();
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
          handleFilesSelected(Array.from(e.dataTransfer.files));
        }
      });

      if (window.innerWidth <= 768) {
        setViewportMode('iphone');
      }

      pollServerStatus();
      setInterval(pollServerStatus, 3000);
    });

    async function uploadRealItem(item, sid) {
      let attempts = 0;
      while (attempts < 3) {
        if (app.isPaused) throw new Error('Transfer paused');
        try {
          await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            activeXhr = xhr;
            xhr.withCredentials = true;
            const url = `${BASE}/upload?batch=${BATCH}&name=${encodeURIComponent(item.name)}&sid=${encodeURIComponent(sid)}`;

            const startTime = Date.now();
            xhr.upload.onprogress = (e) => {
              if (e.lengthComputable && e.total > 0) {
                const pct = Math.min(99, Math.round((e.loaded / e.total) * 100));
                item.progress = pct;
                const fill = document.getElementById(`prog-fill-${item.id}`);
                const pctEl = document.getElementById(`prog-pct-${item.id}`);
                if (fill) fill.style.width = pct + '%';
                if (pctEl) pctEl.textContent = pct + '%';

                const elapsed = (Date.now() - startTime) / 1000;
                if (elapsed > 0.2) {
                  const mbSec = (e.loaded / (1024 * 1024)) / elapsed;
                  const speedEl = document.getElementById('ios-hero-speed');
                  if (speedEl) {
                    speedEl.classList.remove('hidden');
                    speedEl.textContent = mbSec.toFixed(1) + ' MB/s';
                  }
                }
              }
            };

            xhr.onload = () => {
              activeXhr = null;
              if (xhr.status >= 200 && xhr.status < 300) {
                try {
                  const res = JSON.parse(xhr.responseText || '{}');
                  if (res.sid) {
                    window._pd_sid = res.sid;
                    try { sessionStorage.setItem('pd_sid', res.sid); } catch (_) {}
                  }
                } catch (_) {}
                resolve();
              } else {
                let msg = `HTTP ${xhr.status}`;
                try {
                  const res = JSON.parse(xhr.responseText || '{}');
                  if (res.error) msg = res.error;
                } catch (_) {}
                reject(new Error(msg));
              }
            };

            xhr.onerror = () => { activeXhr = null; reject(new Error('Connection dropped. Check Wi-Fi.')); };
            xhr.ontimeout = () => { activeXhr = null; reject(new Error('Upload timeout.')); };
            xhr.onabort = () => { activeXhr = null; reject(new Error('Transfer paused')); };
            xhr.timeout = 180000;

            xhr.open('POST', url);
            if (sid) {
              try { xhr.setRequestHeader('X-PD-Session', sid); } catch (_) {}
            }
            xhr.send(item.file);
          });
          return; // Success!
        } catch (err) {
          if (app.isPaused) throw err;
          attempts++;
          if (attempts >= 3) throw err;
          await new Promise(r => setTimeout(r, 1000 * attempts));
        }
      }
    }

    async function pollServerStatus() {
      try {
        const [stRes, syncRes] = await Promise.allSettled([
          fetch(`${BASE}/status?batch=${BATCH}`),
          fetch(`${BASE}/sync/status`)
        ]);

        if (stRes.status === 'fulfilled' && stRes.value.ok) {
          const data = await stRes.value.json();
          if (data.usable !== undefined) {
            app.freeGB = Number((data.usable / (1024**3)).toFixed(1));
            const pill = document.getElementById('sam-pill-free');
            const freePill = document.getElementById('sam-free-pill');
            const hdr = document.getElementById('ios-header-status');
            const mobPill = document.getElementById('mobile-pill-free');
            if (pill) pill.textContent = `${app.freeGB.toFixed(0)} GB Free`;
            if (freePill) freePill.textContent = `${app.freeGB.toFixed(1)} GB Free`;
            if (hdr) hdr.textContent = `Samsung S24 • ${app.freeGB.toFixed(0)} GB Free`;
            if (mobPill) mobPill.textContent = `${app.freeGB.toFixed(0)}GB Free`;
          }
          if (data.sid && !window._pd_sid) {
            window._pd_sid = data.sid;
            try { sessionStorage.setItem('pd_sid', data.sid); } catch (_) {}
          }
        }

        if (syncRes.status === 'fulfilled' && syncRes.value.ok) {
          const syncData = await syncRes.value.json();
          if (syncData.watermark) {
            app.serverWatermark = syncData.watermark;
            const wmPill = document.getElementById('ios-watermark-pill');
            if (wmPill) wmPill.textContent = `Watermark: ${syncData.watermark.slice(5)}`;
            const swm = document.getElementById('sam-stream-watermark');
            if (swm) swm.textContent = syncData.watermark;
            const sjw = document.getElementById('sam-json-watermark');
            if (sjw) sjw.textContent = `"latest_captured_at": "${syncData.watermark}",`;
          }
          if (syncData.total_synced !== undefined) {
            app.serverTotalSynced = syncData.total_synced;
            const stot = document.getElementById('sam-stream-total');
            if (stot) stot.textContent = `${syncData.total_synced.toLocaleString()} items`;
            const spill = document.getElementById('sam-pill-count');
            if (spill) spill.textContent = `${syncData.total_synced.toLocaleString()} In`;
            const sjc = document.getElementById('sam-json-count');
            if (sjc) sjc.textContent = `"backed_up_assets": ${syncData.total_synced},`;
          }
        }
      } catch (_) {}
    }

    function stopSyncTimer() {
      app.isSyncing = false;
      if (app.syncInterval) {
        clearInterval(app.syncInterval);
        app.syncInterval = null;
      }
    }

    async function startRealtimeSyncLoop(selectedOnly = false) {
      if (app.syncInterval) clearInterval(app.syncInterval);

      // Acquire wake lock if supported
      let wakeLock = null;
      try {
        if ('wakeLock' in navigator) wakeLock = await navigator.wakeLock.request('screen');
      } catch (_) {}

      let sid = window._pd_sid || "";
      if (!sid) {
        try { sid = sessionStorage.getItem("pd_sid") || ""; } catch (_) {}
      }

      const queuePool = app.items.filter(i => !i.synced && (!selectedOnly || i.selected));
      if (queuePool[0] && !queuePool[0].file) queuePool[0].progress = 65;
      if (queuePool[1] && !queuePool[1].file) queuePool[1].progress = 35;
      renderAll();

      while (app.isSyncing && !app.isPaused) {
        const remaining = app.items.filter(i => !i.synced && (!selectedOnly || i.selected));
        if (remaining.length === 0) {
          stopSyncTimer();
          renderAll();
          break;
        }

        const current = remaining[0];
        if (current.file) {
          try {
            await uploadRealItem(current, sid);
            current.progress = 100;
            current.synced = true;
            current.selected = false;
            current.err = false;
            if (current.url && current.url.startsWith('blob:')) {
              URL.revokeObjectURL(current.url);
            }
            const gbDelta = current.sizeMB / 1024;
            app.freeGB = Number(Math.max(0, app.freeGB - gbDelta).toFixed(2));
            if (current.category === 'video') app.videosGB = Number((app.videosGB + gbDelta).toFixed(2));
            else if (current.category === 'raw') app.rawGB = Number((app.rawGB + gbDelta).toFixed(2));
            else app.photosGB = Number((app.photosGB + gbDelta).toFixed(2));
          } catch (err) {
            if (app.isPaused) {
              current.progress = 0;
              break;
            }
            current.err = true;
            current.errMessage = err.message || 'Failed';
            // Stop and let user retry or continue
            stopSyncTimer();
            renderAll();
            break;
          }
        } else {
          // Demo item simulation step
          current.progress = Math.min(100, (current.progress || 0) + 50);
          if (current.progress >= 100) {
            current.synced = true;
            current.selected = false;
            const gbDelta = current.sizeMB / 1024;
            app.freeGB = Number(Math.max(0, app.freeGB - gbDelta).toFixed(2));
            if (current.category === 'video') app.videosGB = Number((app.videosGB + gbDelta).toFixed(2));
            else if (current.category === 'raw') app.rawGB = Number((app.rawGB + gbDelta).toFixed(2));
            else app.photosGB = Number((app.photosGB + gbDelta).toFixed(2));
          }
          await new Promise(r => setTimeout(r, 280));
        }

        renderAll();
        pollServerStatus();
      }

      if (wakeLock) {
        try { await wakeLock.release(); } catch (_) {}
      }
    }

    // --- Simulate Taking a New Photo on iPhone 17 Pro ---
    function simulateNewCapture() {
      const num = app.nextCaptureId++;
      const now = new Date();
      const pad = n => String(n).padStart(2, '0');
      const timeStr = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
      const sampleImgs = [
        'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?auto=format&fit=crop&w=400&q=80',
        'https://images.unsplash.com/photo-1501785888041-af3ef285b470?auto=format&fit=crop&w=400&q=80',
        'https://images.unsplash.com/photo-1519681393784-d120267933ba?auto=format&fit=crop&w=400&q=80'
      ];
      app.items.push({
        id: 'm_' + num,
        title: `iPhone Capture #${num - 4800}`,
        name: `IMG_${num}.HEIC`,
        category: 'photo',
        sizeMB: 3.6,
        dateLabel: `Nov 9 • ${pad(now.getHours())}:${pad(now.getMinutes())}`,
        capturedAt: `2026-11-09 ${timeStr}`,
        synced: false,
        selected: true,
        progress: 0,
        url: sampleImgs[num % sampleImgs.length]
      });
      renderAll();
    }

    // --- Reset Demo to 14 Unsynced Items ---
    function resetDemoState() {
      stopSyncTimer();
      app.items = JSON.parse(JSON.stringify(INITIAL_ITEMS));
      app.freeGB = 142.4;
      app.photosGB = 60.5;
      app.videosGB = 10.5;
      app.rawGB = 8.4;
      app.serverOnline = true;
      renderAll();
    }

    // --- Render iPhone Screen 1: Home ---
    function renderIosHome(stats) {
      document.getElementById('ios-watermark-pill').textContent = `Watermark: ${stats.watermark.slice(5)}`;
      document.getElementById('bubble-photos-sub').textContent = stats.newPhotos > 0 ? `${stats.newPhotos} New` : 'Synced';
      document.getElementById('bubble-videos-sub').textContent = stats.newVideos > 0 ? `${stats.newVideos} New` : 'Synced';
      document.getElementById('bubble-raw-sub').textContent = stats.newRaw > 0 ? `${stats.newRaw} New` : 'Synced';
      document.getElementById('bubble-synced-sub').textContent = stats.totalSynced.toLocaleString();

      const connector = document.getElementById('ios-connector-pill');
      const heroTitle = document.getElementById('ios-hero-title');
      const heroDesc = document.getElementById('ios-hero-desc');
      const heroCtaText = document.getElementById('ios-hero-cta-text');
      const heroSpeed = document.getElementById('ios-hero-speed');
      const bellDot = document.getElementById('ios-bell-dot');
      const islandText = document.getElementById('ios-island-text');

      if (!app.serverOnline) {
        connector.textContent = 'Samsung S24 Offline • Check Tunnel';
        heroTitle.textContent = 'Samsung Server Paused';
        heroDesc.textContent = 'Tap below to wake the Samsung receiver daemon and resume catch-up.';
        heroCtaText.textContent = 'Wake & Sync Now';
        heroSpeed.classList.add('hidden');
        islandText.textContent = 'WAIT';
        return;
      }

      if (app.isPaused) {
        connector.textContent = `Transfer Paused • ${stats.unsyncedCount} Remaining`;
        heroTitle.textContent = 'Transfer Paused';
        heroDesc.textContent = `Tap below to resume streaming ${stats.unsyncedCount} photos (${stats.deltaMB} MB) to Samsung.`;
        heroCtaText.textContent = `▶ Resume Backing Up (${stats.unsyncedCount} Left)`;
        heroSpeed.classList.add('hidden');
        bellDot.classList.remove('hidden');
        islandText.textContent = 'PAUSED';
        return;
      }

      if (app.isSyncing) {
        connector.textContent = `Pushing ${stats.unsyncedCount} Left • ${stats.deltaMB} MB`;
        heroTitle.textContent = `Backing Up (${stats.unsyncedCount} Left)...`;
        heroDesc.textContent = `Streaming directly to Samsung S24 Ultra over local WireGuard tunnel.`;
        heroCtaText.textContent = '⏸ Pause Transfer';
        heroSpeed.classList.remove('hidden');
        bellDot.classList.remove('hidden');
        islandText.textContent = `${stats.unsyncedCount} UP`;
      } else if (stats.unsyncedCount === 0) {
        if (app.items.length === 0) {
          connector.textContent = `Ready to Sync • Direct to Samsung`;
          heroTitle.textContent = 'Add Photos to Back Up';
          heroDesc.textContent = 'Pick photos, videos, or ProRAW from your iPhone to stream directly to Samsung.';
          heroCtaText.textContent = 'Select Photos & Videos';
        } else {
          connector.textContent = `0 Unsynced • All ${stats.totalSynced.toLocaleString()} Backed Up`;
          heroTitle.textContent = 'All Caught Up!';
          heroDesc.textContent = `Every photo & video up to ${stats.watermark.slice(11)} is safely stored on Samsung.`;
          heroCtaText.textContent = '+ Add More Photos';
        }
        heroSpeed.classList.add('hidden');
        bellDot.classList.add('hidden');
        islandText.textContent = 'READY';
      } else {
        connector.textContent = `${stats.unsyncedCount} Unsynced Items • ${stats.deltaMB} MB Delta`;
        heroTitle.textContent = `${stats.unsyncedCount} New Photos Waiting`;
        heroDesc.textContent = `Captured after your last Samsung backup (${stats.watermark.slice(5, 16)}).`;
        heroCtaText.textContent = `Back Up ${stats.unsyncedCount} Items Now`;
        heroSpeed.classList.add('hidden');
        bellDot.classList.remove('hidden');
        islandText.textContent = `${stats.unsyncedCount} NEW`;
      }
    }

    // --- Render iPhone Screen 2: Photos Grid (Mode B Selective Picker) ---
    function renderIosPhotosScreen() {
      const stats = getDeltaStats();
      const btnUnsynced = document.getElementById('seg-btn-unsynced');
      const btnAll = document.getElementById('seg-btn-all');

      btnUnsynced.textContent = `Unsynced (${stats.unsyncedCount})`;
      btnAll.textContent = `All Library (${app.items.length})`;

      if (app.photoFilter === 'unsynced') {
        btnUnsynced.className = 'py-2.5 rounded-full text-xs font-bold bg-electric text-white shadow-xs transition-all tabular-nums';
        btnAll.className = 'py-2.5 rounded-full text-xs font-bold bg-white text-zinc-700 hover:bg-zinc-100 transition-all tabular-nums';
      } else {
        btnAll.className = 'py-2.5 rounded-full text-xs font-bold bg-electric text-white shadow-xs transition-all tabular-nums';
        btnUnsynced.className = 'py-2.5 rounded-full text-xs font-bold bg-white text-zinc-700 hover:bg-zinc-100 transition-all tabular-nums';
      }

      const list = app.photoFilter === 'unsynced'
        ? app.items.filter(i => !i.synced)
        : app.items.slice().reverse();

      const grid = document.getElementById('ios-photo-grid');
      if (list.length === 0) {
        grid.innerHTML = `
          <div class="col-span-2 bg-white rounded-[24px] p-6 text-center shadow-soft">
            <div class="w-10 h-10 rounded-full bg-emerald-100 text-emerald-700 mx-auto flex items-center justify-center mb-2">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg>
            </div>
            <div class="text-xs font-extrabold text-zinc-900">Zero Unsynced Photos</div>
            <p class="text-[11px] text-zinc-500 mt-0.5">Switch to "All Library" or tap "+ Add" above.</p>
          </div>
        `;
      } else {
        grid.innerHTML = list.slice(0, 300).map(item => {
          const isSelected = item.selected && !item.synced;
          return `
            <div onclick="togglePhotoSelect('${item.id}')"
              class="group cursor-pointer">
              <div class="relative aspect-square rounded-[22px] overflow-hidden bg-zinc-200 shadow-xs border-2 transition-all ${
                isSelected ? 'border-electric scale-[0.98]' : 'border-transparent'
              } ${item.synced ? 'opacity-65' : ''}">
                ${item.url ? `
                  <img src="${item.url}" alt="${item.title}" loading="lazy" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300" />
                ` : `
                  <div class="w-full h-full bg-zinc-100 flex items-center justify-center font-bold text-xs text-zinc-500">${item.category.toUpperCase()}</div>
                `}
                
                <!-- Top-Right Frosted Pill Badge -->
                <div class="absolute top-2.5 right-2.5">
                  ${item.synced ? `
                    <span class="px-2.5 py-0.5 rounded-full bg-emerald-500/90 backdrop-blur-xs text-white text-[10px] font-bold shadow-xs">
                      Synced ✓
                    </span>
                  ` : `
                    <span class="px-2.5 py-0.5 rounded-full ${
                      isSelected ? 'bg-electric text-white' : 'bg-white/85 text-zinc-900'
                    } backdrop-blur-xs text-[10px] font-extrabold tabular-nums shadow-xs">
                      ${isSelected ? 'Selected' : `${item.sizeMB}M`}
                    </span>
                  `}
                </div>
              </div>
              <div class="mt-1.5 px-1">
                <div class="text-xs font-extrabold text-zinc-900 truncate">${item.title}</div>
                <div class="text-[10px] font-medium text-zinc-500 tabular-nums">${item.dateLabel}</div>
              </div>
            </div>
          `;
        }).join('');
      }

      const selectedItems = app.items.filter(i => !i.synced && i.selected);
      const selMB = selectedItems.reduce((s, i) => s + i.sizeMB, 0).toFixed(1);
      const btn = document.getElementById('ios-sync-selected-btn');
      const label = document.getElementById('ios-sync-selected-label');
      const mbSpan = document.getElementById('ios-sync-selected-mb');

      if (selectedItems.length === 0) {
        btn.className = 'w-full py-3.5 px-5 rounded-full bg-zinc-200 text-zinc-500 text-xs font-bold flex items-center justify-between cursor-not-allowed';
        label.textContent = 'Tap Photos Above to Select';
        mbSpan.textContent = '0 MB';
      } else {
        btn.className = 'w-full py-3.5 px-5 rounded-full bg-electric hover:bg-blue-700 active:scale-[0.99] text-white text-xs font-extrabold shadow-md flex items-center justify-between transition-all';
        label.textContent = `Push ${selectedItems.length} Selected Photo${selectedItems.length === 1 ? '' : 's'}`;
        mbSpan.textContent = `${selMB} MB →`;
      }
    }

    // --- Render iPhone Screen 3: File Upload Progress Queue ---
    function renderIosQueueScreen(stats) {
      const container = document.getElementById('ios-upload-queue-list');
      const badge = document.getElementById('ios-queue-count-badge');
      const statusLabel = document.getElementById('ios-queue-status-label');

      badge.textContent = stats.unsyncedCount > 0 ? `${stats.unsyncedCount} remaining` : 'All Complete';
      statusLabel.textContent = app.isSyncing ? 'Streaming...' : (app.isPaused ? 'Paused' : (stats.unsyncedCount > 0 ? 'Pending' : 'Completed'));

      const totalItems = app.items.length;
      const syncedItems = app.items.filter(i => i.synced).length;
      const totalMB = app.items.reduce((s, i) => s + i.sizeMB, 0).toFixed(1);
      const syncedMB = app.items.filter(i => i.synced).reduce((s, i) => s + i.sizeMB, 0).toFixed(1);
      const overallPct = totalItems > 0 ? Math.round((syncedItems / totalItems) * 100) : 0;

      const batchCardHtml = `
        <div class="bg-white rounded-2xl p-4 shadow-soft space-y-2.5 mb-3">
          <div class="flex items-center justify-between text-xs font-extrabold text-zinc-900">
            <span>Overall Queue (${syncedItems} of ${totalItems} synced)</span>
            <span class="font-mono text-electric tabular-nums">${overallPct}% · ${syncedMB}/${totalMB} MB</span>
          </div>
          <div class="w-full h-2.5 rounded-full bg-zinc-100 overflow-hidden">
            <div class="h-full bg-electric rounded-full transition-all duration-300" style="width: ${overallPct}%"></div>
          </div>
          <div class="flex items-center justify-between pt-1">
            <button type="button" onclick="togglePlayPause()"
              class="px-3.5 py-1.5 rounded-full text-xs font-bold flex items-center gap-1.5 transition-all shadow-xs ${
                app.isSyncing ? 'bg-amber-100 text-amber-900 hover:bg-amber-200' : 'bg-electric text-white hover:bg-blue-700'
              }">
              ${app.isSyncing ? '⏸ Pause' : (app.isPaused ? '▶ Resume' : '▶ Start Transfer')}
            </button>
            <button type="button" onclick="checkServerDuplicates()"
              class="px-2.5 py-1.5 rounded-full bg-zinc-100 hover:bg-zinc-200 text-[11px] font-bold text-zinc-600 flex items-center gap-1 transition-all"
              title="Query Samsung for already-synced files and skip them">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
              <span>Smart Resume Check</span>
            </button>
          </div>
        </div>
      `;

      const allItems = stats.unsynced.length > 0 ? stats.unsynced : stats.synced.slice().reverse();
      const limit = app.showAllQueue ? allItems.length : 40;
      const displayItems = allItems.slice(0, limit);

      const pastelPalette = [
        { bg: 'bg-[#FFF1B8]', text: 'text-amber-800' },
        { bg: 'bg-[#DECFFF]', text: 'text-purple-800' },
        { bg: 'bg-[#DCEBFF]', text: 'text-electric' },
        { bg: 'bg-[#DFF2E6]', text: 'text-emerald-800' }
      ];

      const listHtml = displayItems.map((item, idx) => {
        const tone = pastelPalette[idx % pastelPalette.length];
        const pct = item.synced ? 100 : (item.progress || (idx === 0 && app.isSyncing ? 80 : idx === 1 && app.isSyncing ? 45 : 0));
        let itemStatus = 'Waiting';
        if (item.synced) itemStatus = 'Saved to Samsung S24';
        else if (item.err) itemStatus = item.errMessage || 'Error · Tap to retry';
        else if (app.isSyncing && idx === 0) itemStatus = 'Uploading...';
        else if (app.isPaused) itemStatus = 'Paused';

        return `
          <div class="bg-white rounded-2xl p-3 flex items-center justify-between gap-2 shadow-soft">
            <div class="flex items-center gap-3 min-w-0">
              ${item.url ? `
                <img src="${item.url}" class="w-10 h-10 rounded-xl object-cover flex-shrink-0" />
              ` : `
                <div class="w-10 h-10 rounded-xl ${tone.bg} ${tone.text} flex items-center justify-center flex-shrink-0 font-mono text-[10px] font-extrabold">
                  ${item.category.toUpperCase()}
                </div>
              `}
              <div class="min-w-0">
                <div class="text-xs font-extrabold text-zinc-900 truncate">${item.name}</div>
                <div class="text-[10px] font-medium text-zinc-400 tabular-nums">
                  ${item.sizeMB} MB • ${itemStatus}
                </div>
              </div>
            </div>

            <!-- Compact Black Pill Progress Bar + Bold Percentage + Action Circles -->
            <div class="flex items-center gap-2 flex-shrink-0">
              <div class="w-10 h-2 rounded-full bg-zinc-200 overflow-hidden">
                <div class="h-full bg-pillnav rounded-full transition-all duration-200" id="prog-fill-${item.id}" style="width: ${pct}%"></div>
              </div>
              <span id="prog-pct-${item.id}" class="text-xs font-extrabold text-zinc-900 tabular-nums w-8 text-right">${pct}%</span>
              ${!item.synced ? `
                <button type="button" onclick="syncSingleItemNow('${item.id}')"
                  title="Upload Immediately"
                  class="w-7 h-7 rounded-full bg-electric text-white flex items-center justify-center hover:bg-blue-700">
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2.3" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/></svg>
                </button>
              ` : `
                <span class="w-7 h-7 rounded-full bg-emerald-100 text-emerald-700 flex items-center justify-center">
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg>
                </span>
              `}
            </div>
          </div>
        `;
      }).join('');

      let toggleAllHtml = '';
      if (allItems.length > 40 && !app.showAllQueue) {
        toggleAllHtml = `
          <button type="button" onclick="app.showAllQueue=true; renderAll();"
            class="w-full py-2.5 rounded-xl bg-white border border-zinc-200 text-xs font-bold text-zinc-700 hover:bg-zinc-50 shadow-xs">
            Show all ${allItems.length} queued files
          </button>
        `;
      }

      container.innerHTML = batchCardHtml + listHtml + toggleAllHtml;
    }

    async function syncSingleItemNow(id) {
      const item = app.items.find(i => i.id === id);
      if (!item || item.synced) return;
      if (item.file) {
        let sid = window._pd_sid || "";
        if (!sid) {
          try { sid = sessionStorage.getItem("pd_sid") || ""; } catch (_) {}
        }
        try {
          await uploadRealItem(item, sid);
          item.synced = true;
          item.progress = 100;
          item.selected = false;
          item.err = false;
          if (item.url && item.url.startsWith('blob:')) {
            URL.revokeObjectURL(item.url);
          }
          const gbDelta = item.sizeMB / 1024;
          app.freeGB = Number(Math.max(0, app.freeGB - gbDelta).toFixed(2));
          if (item.category === 'video') app.videosGB = Number((app.videosGB + gbDelta).toFixed(2));
          else if (item.category === 'raw') app.rawGB = Number((app.rawGB + gbDelta).toFixed(2));
          else app.photosGB = Number((app.photosGB + gbDelta).toFixed(2));
        } catch (err) {
          item.err = true;
          item.errMessage = err.message || 'Failed';
          alert('Upload failed: ' + (err.message || 'Check connection'));
        }
      } else {
        item.synced = true;
        item.progress = 100;
        item.selected = false;
        const gbDelta = item.sizeMB / 1024;
        app.freeGB = Number(Math.max(0, app.freeGB - gbDelta).toFixed(2));
      }
      renderAll();
    }

    // --- Render Samsung APK Screens ---
    function renderSamsungScreens(stats) {
      const dot = document.getElementById('sam-daemon-dot');
      const badge = document.getElementById('sam-http-badge');
      const toggleBtn = document.getElementById('sam-server-toggle-btn');

      if (app.serverOnline) {
        dot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-500 flex-shrink-0';
        badge.textContent = app.isSyncing ? '201 WRITING' : '200 OK';
        badge.className = 'text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800';
        toggleBtn.className = 'w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-emerald-600 hover:bg-zinc-50 transition-colors';
      } else {
        dot.className = 'w-2.5 h-2.5 rounded-full bg-rose-500 flex-shrink-0';
        badge.textContent = 'OFFLINE';
        badge.className = 'text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-700';
        toggleBtn.className = 'w-10 h-10 rounded-full bg-rose-50 border border-rose-200 flex items-center justify-center text-rose-600';
      }

      // Update Pills & Folder Meta
      document.getElementById('sam-pill-count').textContent = `${stats.totalSynced.toLocaleString()} In`;
      document.getElementById('sam-pill-free').textContent = `${app.freeGB.toFixed(0)} GB Free`;
      document.getElementById('sam-folder-photos-meta').textContent = `${app.photosGB.toFixed(1)} GB • ${(stats.totalSynced - 296).toLocaleString()} HEIC`;
      document.getElementById('sam-folder-videos-meta').textContent = `${app.videosGB.toFixed(1)} GB • 214 MOV`;
      document.getElementById('sam-folder-raw-meta').textContent = `${app.rawGB.toFixed(1)} GB • 82 DNG`;
      document.getElementById('sam-folder-ledger-meta').textContent = `Watermark: ${stats.watermark.slice(5, 16)}`;

      // Update Stream Screen
      document.getElementById('sam-stream-watermark').textContent = stats.watermark;
      document.getElementById('sam-stream-total').textContent = `${stats.totalSynced.toLocaleString()} items`;
      const livePill = document.getElementById('sam-stream-live-pill');
      livePill.textContent = app.isSyncing ? 'Receiving...' : 'Listening';
      livePill.className = app.isSyncing
        ? 'px-2.5 py-1 rounded-full bg-electric text-white text-[10px] font-extrabold uppercase animate-pulse'
        : 'px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-800 text-[10px] font-extrabold uppercase';

      const recentSynced = stats.synced.slice(-5).reverse();
      const streamContainer = document.getElementById('sam-incoming-list');
      streamContainer.innerHTML = recentSynced.map(item => `
        <div class="bg-white rounded-2xl p-3 flex items-center justify-between shadow-soft">
          <div class="flex items-center gap-3 min-w-0">
            <img src="${item.url}" alt="${item.name}" class="w-10 h-10 rounded-xl object-cover flex-shrink-0" />
            <div class="min-w-0">
              <div class="text-xs font-extrabold text-zinc-900 truncate">${item.name}</div>
              <div class="text-[10px] font-mono text-zinc-500 tabular-nums">Captured ${item.capturedAt.slice(5)}</div>
            </div>
          </div>
          <div class="text-right flex-shrink-0">
            <span class="px-2 py-0.5 rounded-full bg-[#DFF2E6] text-emerald-800 text-[10px] font-extrabold tabular-nums">
              +${item.sizeMB} MB
            </span>
          </div>
        </div>
      `).join('');

      // Update Settings JSON Preview
      document.getElementById('sam-free-pill').textContent = `${app.freeGB.toFixed(1)} GB Free`;
      document.getElementById('sam-json-watermark').textContent = `"latest_captured_at": "${stats.watermark}",`;
      document.getElementById('sam-json-count').textContent = `"backed_up_assets": ${stats.totalSynced},`;
      document.getElementById('sam-json-free').textContent = `"free_space_gb": ${app.freeGB.toFixed(1)}`;
    }

    function renderAll() {
      const stats = getDeltaStats();
      renderIosHome(stats);
      renderIosPhotosScreen();
      renderIosQueueScreen(stats);
      renderSamsungScreens(stats);
    }

    window.onload = function () {
      if (window.innerWidth < 1024) {
        setViewportMode('iphone');
      }
      renderAll();
      pollServerStatus();
    };
  </script>
</body>
</html>"""

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
