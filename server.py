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
    <p class="muted" style="margin-top:4px">Remove stalled .part files older than 5 minutes or reset session history.</p>
    <div class="row">
      <button class="btn ghost" id="clearBtn" type="button">Clear temp cache</button>
      <button class="btn ghost" id="clearSessionsBtn" type="button" style="color:#ef4444;border-color:rgba(239,68,68,0.3)">Clear sessions</button>
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
  var CLEAR_SESSIONS = $clear_sessions_url_js;
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

  var clearSessionsBtn = document.getElementById("clearSessionsBtn");
  var clearingSessions = false;
  clearSessionsBtn.addEventListener("click", function () {
    if (clearingSessions) return;
    if (clearSessionsBtn.getAttribute("data-confirm") !== "1") {
      clearSessionsBtn.setAttribute("data-confirm", "1");
      clearSessionsBtn.textContent = "Confirm clear sessions?";
      setTimeout(function () {
        if (clearSessionsBtn.getAttribute("data-confirm") !== "1") return;
        clearSessionsBtn.setAttribute("data-confirm", "0");
        clearSessionsBtn.textContent = "Clear sessions";
      }, 3500);
      return;
    }
    clearSessionsBtn.setAttribute("data-confirm", "0");
    clearSessionsBtn.disabled = true;
    clearSessionsBtn.textContent = "Resetting…";
    clearingSessions = true;
    fetch(CLEAR_SESSIONS, {method: "POST"})
      .then(function (response) { return response.json(); })
      .then(function (result) {
        document.getElementById("houseState").textContent = result.ok
          ? "Cleared all sessions and batches."
          : "Could not reset sessions.";
        refresh(true);
      })
      .catch(function () {
        document.getElementById("houseState").textContent = "Error resetting sessions.";
      })
      .then(function () {
        clearingSessions = false;
        clearSessionsBtn.disabled = false;
        clearSessionsBtn.textContent = "Clear sessions";
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
  <meta name="theme-color" content="#ECEEF0">

  <title>Photo Drop — Sync to Samsung Galaxy</title>
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
            board: '#ECEEF0',
            appbg: '#F5F6F7',
            electric: '#1E50FF',
            lavender: { card: '#DECFFF', deep: '#CBB5FF' },
            butter: { card: '#FFF1B8', deep: '#FBE38E' },
            mint: { card: '#DFF2E6', deep: '#C5E8D2' },
            pillnav: '#141519'
          },
          boxShadow: {
            'soft': '0 4px 20px -2px rgba(20, 21, 25, 0.05)',
            'pill': '0 10px 25px -4px rgba(20, 21, 25, 0.28)',
            'float': '0 4px 12px rgba(20, 21, 25, 0.08)'
          }
        }
      }
    }
  </script>
  <style>
    .tabular-nums { font-variant-numeric: tabular-nums; }
    .no-scrollbar::-webkit-scrollbar { display: none; }
    .no-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
  </style>
</head>
<body class="bg-board text-zinc-900 font-sans antialiased min-h-screen selection:bg-electric selection:text-white pb-24">
  <input type="file" id="real-file-picker" multiple accept="image/*,video/*" style="display:none;" />

  <!-- Main Responsive Container (Full screen on mobile, elegant max-w-md on desktop) -->
  <div class="w-full max-w-md mx-auto px-4 pt-4 sm:pt-6 flex flex-col gap-4">

    <!-- Top Profile & Bell Row (Exact Studio Header) -->
    <header class="flex items-center justify-between pt-1">
      <div class="flex items-center gap-3">
        <div class="w-11 h-11 rounded-full bg-[#D8F3DC] border-2 border-white shadow-xs overflow-hidden flex items-center justify-center">
          <img src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&w=120&q=80" alt="Profile" class="w-full h-full object-cover" />
        </div>
        <div>
          <div class="text-xs font-bold text-zinc-900">Hi, iPhone 17 Pro</div>
          <div id="ios-header-status" class="text-[11px] font-medium text-zinc-500 tabular-nums">Samsung Galaxy &bull; 105 GB Free</div>
        </div>
      </div>
      <button type="button" onclick="switchIosTab('queue')" aria-label="Open Upload Queue"
        class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-700 hover:bg-zinc-100 transition-colors relative shadow-xs">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
        </svg>
        <span id="ios-bell-dot" class="w-2 h-2 rounded-full bg-electric absolute top-2.5 right-2.5"></span>
      </button>
    </header>

    <!-- Editorial Bold Title -->
    <h1 class="text-[26px] font-extrabold tracking-tight text-zinc-900 leading-tight">
      Sync With Samsung
    </h1>

    <!-- Search / Watermark Pill Bar -->
    <div class="bg-white rounded-full px-4 py-3 flex items-center justify-between shadow-soft">
      <div class="flex items-center gap-2.5 min-w-0">
        <span id="ios-tunnel-dot" class="w-2.5 h-2.5 rounded-full bg-emerald-500 flex-shrink-0"></span>
        <span id="ios-watermark-pill" class="text-xs font-medium text-zinc-500 truncate tabular-nums">
          Watermark: Live &amp; Ready
        </span>
      </div>
      <button type="button" onclick="switchIosTab('photos')" class="text-zinc-700 hover:text-electric transition-colors" title="Filter Unsynced Photos">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 6h9.75M10.5 6a1.5 1.5 0 11-3 0m3 0a1.5 1.5 0 10-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-9.75 0h9.75" />
        </svg>
      </button>
    </div>

    <!-- ================================================================= -->
    <!-- SCREEN 1: HOME (Delta + Butter Card + Chips + Dropzone)            -->
    <!-- ================================================================= -->
    <main id="ios-screen-home" class="space-y-4">

      <!-- LAVENDER FEATURE CARD: Unbacked Delta & Library -->
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

          <!-- 4 Circular Icon Bubbles -->
          <div class="grid grid-cols-4 gap-2 text-center">
            <!-- Bubble 1: Photos -->
            <button type="button" onclick="switchIosTab('photos')" class="flex flex-col items-center group">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-xs group-hover:scale-105 transition-transform">
                <span class="w-6 h-6 rounded-md bg-orange-100 text-orange-500 flex items-center justify-center">
                  <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z" clip-rule="evenodd"/></svg>
                </span>
              </div>
              <span class="mt-2 text-[11px] font-bold text-zinc-900">Photos</span>
              <span id="bubble-photos-sub" class="text-[10px] font-medium text-zinc-600 tabular-nums">0 New</span>
            </button>

            <!-- Bubble 2: Videos -->
            <button type="button" onclick="switchIosTab('photos')" class="flex flex-col items-center group">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-xs group-hover:scale-105 transition-transform">
                <span class="w-6 h-6 rounded-md bg-blue-100 text-electric flex items-center justify-center">
                  <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path d="M2 6a2 2 0 012-2h6a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V6zM14.553 7.106A1 1 0 0014 8v4a1 1 0 00.553.894l2 1A1 1 0 0018 13V7a1 1 0 00-1.447-.894l-2 1z"/></svg>
                </span>
              </div>
              <span class="mt-2 text-[11px] font-bold text-zinc-900">Videos</span>
              <span id="bubble-videos-sub" class="text-[10px] font-medium text-zinc-600 tabular-nums">0 New</span>
            </button>

            <!-- Bubble 3: ProRAW -->
            <button type="button" onclick="switchIosTab('photos')" class="flex flex-col items-center group">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-xs group-hover:scale-105 transition-transform">
                <span class="w-6 h-6 rounded-md bg-rose-100 text-rose-500 flex items-center justify-center font-mono text-[9px] font-extrabold">RAW</span>
              </div>
              <span class="mt-2 text-[11px] font-bold text-zinc-900">ProRAW</span>
              <span id="bubble-raw-sub" class="text-[10px] font-medium text-zinc-600 tabular-nums">0 New</span>
            </button>

            <!-- Bubble 4: Already Synced -->
            <button type="button" onclick="switchIosTab('photos')" class="flex flex-col items-center group">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-xs group-hover:scale-105 transition-transform">
                <span class="w-6 h-6 rounded-md bg-purple-100 text-purple-600 flex items-center justify-center">
                  <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg>
                </span>
              </div>
              <span class="mt-2 text-[11px] font-bold text-zinc-900">Synced</span>
              <span id="bubble-synced-sub" class="text-[10px] font-medium text-zinc-600 tabular-nums">1</span>
            </button>
          </div>
        </div>

        <!-- Floating Connector Pill -->
        <div class="absolute -bottom-1.5 inset-x-0 flex justify-center">
          <div id="ios-connector-pill" class="px-4 py-1 rounded-full bg-white shadow-float border border-zinc-100 text-[10px] font-bold text-zinc-700 tabular-nums">
            Ready to Sync &bull; Direct to Samsung
          </div>
        </div>
      </div>

      <!-- WARM BUTTER YELLOW HERO CARD -->
      <div class="bg-butter-card rounded-[26px] p-4 shadow-soft relative overflow-hidden">
        <div class="w-20 h-20 rounded-full bg-white/50 absolute -top-6 -right-6 pointer-events-none"></div>
        <div class="w-12 h-12 rounded-full bg-white/60 absolute top-6 right-8 pointer-events-none"></div>

        <div class="relative z-10">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-extrabold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-white/80 text-zinc-800">
              Mode A &bull; Auto Catch-Up
            </span>
            <span id="ios-hero-speed" class="text-[11px] font-mono font-bold text-zinc-700 tabular-nums hidden">
              0.0 MB/s
            </span>
          </div>

          <h3 id="ios-hero-title" class="mt-2.5 text-lg font-extrabold text-zinc-900 leading-snug">
            Add Photos to Back Up
          </h3>
          <p id="ios-hero-desc" class="mt-1 text-xs font-medium text-zinc-600 leading-relaxed max-w-[280px]">
            Pick photos, videos, or ProRAW from your iPhone to stream directly to Samsung Galaxy.
          </p>

          <!-- Signature White Pill CTA Button with Black Circle Right Arrow -->
          <button type="button" onclick="triggerOneTapSync()" id="ios-hero-cta"
            class="mt-4 w-full bg-white hover:bg-zinc-50 active:scale-[0.99] rounded-full pl-5 pr-2 py-2 flex items-center justify-between shadow-soft transition-all group">
            <span id="ios-hero-cta-text" class="text-xs font-extrabold text-zinc-900 tabular-nums">
              Select Photos &amp; Videos Now
            </span>
            <span id="ios-hero-cta-icon" class="w-8 h-8 rounded-full bg-pillnav text-white flex items-center justify-center group-hover:translate-x-0.5 transition-transform">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
              </svg>
            </span>
          </button>
        </div>
      </div>

      <!-- 3 Pastel Action Chips -->
      <div class="grid grid-cols-3 gap-2 pt-0.5">
        <button type="button" onclick="triggerOneTapSync()"
          class="py-2.5 px-3 rounded-full bg-[#DFF2E6] hover:brightness-95 text-zinc-900 text-xs font-bold flex items-center justify-center gap-1.5 transition-all shadow-xs">
          <svg class="w-3.5 h-3.5 text-emerald-700" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/></svg>
          <span>1-Tap</span>
        </button>
        <button type="button" onclick="switchIosTab('photos')"
          class="py-2.5 px-3 rounded-full bg-[#FADCE6] hover:brightness-95 text-zinc-900 text-xs font-bold flex items-center justify-center gap-1.5 transition-all shadow-xs">
          <svg class="w-3.5 h-3.5 text-rose-700" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg>
          <span>Select</span>
        </button>
        <button type="button" onclick="switchIosTab('queue')"
          class="py-2.5 px-3 rounded-full bg-[#DCEBFF] hover:brightness-95 text-zinc-900 text-xs font-bold flex items-center justify-center gap-1.5 transition-all shadow-xs">
          <svg class="w-3.5 h-3.5 text-electric" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z"/></svg>
          <span>Queue</span>
        </button>
      </div>

      <!-- Drag & Drop Zone -->
      <div onclick="pickRealPhotos()"
        class="border-2 border-dashed border-zinc-300 hover:border-electric bg-white/70 hover:bg-white rounded-[24px] p-6 text-center cursor-pointer transition-all shadow-soft group">
        <div class="w-12 h-12 rounded-full bg-blue-50 text-electric mx-auto flex items-center justify-center mb-2.5 group-hover:scale-105 transition-transform">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/>
          </svg>
        </div>
        <div class="text-xs font-extrabold text-zinc-900">Drag photos here or tap to pick</div>
        <p class="text-[11px] text-zinc-500 mt-0.5">Supports 500+ items &bull; Original quality HEIC, MOV, ProRAW</p>
      </div>

    </main>

    <!-- ================================================================= -->
    <!-- SCREEN 2: SELECTIVE PHOTOS GRID                                   -->
    <!-- ================================================================= -->
    <section id="ios-screen-photos" class="hidden space-y-4">
      <div class="flex items-center justify-between pt-1">
        <button type="button" onclick="switchIosTab('home')"
          class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800 hover:bg-zinc-100 shadow-xs">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18"/></svg>
        </button>
        <h2 class="text-base font-extrabold text-zinc-900">Selective Sync</h2>
        <div class="flex items-center gap-1.5">
          <button type="button" onclick="pickRealPhotos()"
            class="px-3 h-9 rounded-full bg-electric text-white text-[11px] font-bold hover:bg-blue-700 flex items-center gap-1 shadow-xs">
            <span>+ Add</span>
          </button>
          <button type="button" onclick="toggleSelectAllUnsynced()" id="ios-select-all-btn"
            class="px-3 h-9 rounded-full bg-white border border-zinc-200/80 text-[11px] font-bold text-electric hover:bg-zinc-50">
            All New
          </button>
        </div>
      </div>

      <!-- Search / Filter Bar -->
      <div class="bg-white rounded-full px-4 py-2.5 flex items-center justify-between shadow-soft">
        <div class="flex items-center gap-2 text-xs text-zinc-500">
          <svg class="w-4 h-4 text-zinc-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/></svg>
          <span id="ios-photo-filter-summary">Skipping files already on Samsung</span>
        </div>
        <span class="text-[11px] font-mono font-bold text-emerald-600">SHA-256</span>
      </div>

      <!-- Segmented Pill Toggle -->
      <div class="grid grid-cols-2 gap-2.5">
        <button type="button" onclick="setPhotoFilter('unsynced')" id="seg-btn-unsynced"
          class="py-2.5 rounded-full text-xs font-bold bg-electric text-white shadow-xs transition-all tabular-nums">
          Unsynced (0)
        </button>
        <button type="button" onclick="setPhotoFilter('all')" id="seg-btn-all"
          class="py-2.5 rounded-full text-xs font-bold bg-white text-zinc-700 hover:bg-zinc-100 transition-all tabular-nums">
          All Library (0)
        </button>
      </div>

      <!-- 2-Column Rounded Photo Cards Grid -->
      <div id="ios-photo-grid" class="grid grid-cols-2 gap-3 pt-1">
        <!-- Populated by JS -->
      </div>

      <!-- Sticky Action Button When Items Selected -->
      <div class="pt-1">
        <button type="button" onclick="syncSelectedPhotos()" id="ios-sync-selected-btn"
          class="w-full py-3.5 px-5 rounded-full bg-zinc-200 text-zinc-500 text-xs font-bold flex items-center justify-between cursor-not-allowed transition-all">
          <span id="ios-sync-selected-label" class="tabular-nums">Tap Photos Above to Select</span>
          <span id="ios-sync-selected-mb" class="font-mono text-[11px] opacity-90 tabular-nums">0 MB &rarr;</span>
        </button>
      </div>
    </section>

    <!-- ================================================================= -->
    <!-- SCREEN 3: FILE UPLOAD QUEUE                                       -->
    <!-- ================================================================= -->
    <section id="ios-screen-queue" class="hidden space-y-4">
      <div class="flex items-center justify-between pt-1">
        <button type="button" onclick="switchIosTab('home')"
          class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800 hover:bg-zinc-100 shadow-xs">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18"/></svg>
        </button>
        <h2 class="text-base font-extrabold text-zinc-900">File Upload Queue</h2>
        <button type="button" onclick="triggerOneTapSync()"
          class="w-10 h-10 rounded-full bg-white border border-zinc-200/80 flex items-center justify-center text-zinc-800 hover:bg-zinc-100 shadow-xs" title="Start All">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/></svg>
        </button>
      </div>

      <div class="flex items-center justify-between pt-1">
        <span id="ios-queue-status-label" class="text-sm font-extrabold text-zinc-900">Queue Ready</span>
        <div class="flex items-center gap-1.5">
          <span class="px-2.5 py-1 rounded-full bg-white text-[11px] font-mono font-bold text-zinc-700 shadow-xs tabular-nums" id="ios-queue-count-badge">
            0 items
          </span>
        </div>
      </div>

      <!-- Upload Progress Cards -->
      <div id="ios-upload-queue-list" class="space-y-2.5">
        <!-- Populated by JS -->
      </div>
    </section>

  </div>

  <!-- =================================================================== -->
  <!-- SIGNATURE FLOATING BLACK PILL BOTTOM NAV BAR (Matches Reference)    -->
  <!-- =================================================================== -->
  <div class="fixed bottom-5 inset-x-6 max-w-sm mx-auto z-40">
    <nav aria-label="iPhone Navigation" class="bg-pillnav rounded-full p-2 flex items-center justify-between shadow-pill">
      <!-- Tab 1: Home -->
      <button type="button" onclick="switchIosTab('home')" id="ios-nav-home"
        aria-label="Home"
        class="w-10 h-10 rounded-full bg-white text-zinc-900 flex items-center justify-center transition-all shadow-xs">
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

      <!-- CENTER ELECTRIC BLUE '+' PICKER TRIGGER -->
      <button type="button" onclick="pickRealPhotos()" id="ios-nav-center-plus"
        title="Add Photos from Camera Roll"
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
    </nav>
  </div>

  <script>
    const BASE = "{{BASE}}";
    const TOKEN = "{{TOKEN}}";
    function randomHex(len) {
      const arr = new Uint8Array(Math.ceil(len / 2));
      crypto.getRandomValues(arr);
      return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, len);
    }
    const BATCH = randomHex(12);
    let activeXhr = null;

    const app = {
      items: [],
      iosTab: 'home',
      photoFilter: 'unsynced',
      serverOnline: true,
      isSyncing: false,
      isPaused: false,
      showAllQueue: false,
      freeGB: 105.5,
      serverWatermark: 'Live',
      serverTotalSynced: 0,
      photosGB: 0,
      videosGB: 0,
      rawGB: 0
    };

    function pickRealPhotos() {
      const picker = document.getElementById('real-file-picker');
      if (picker) picker.click();
    }

    function getDeltaStats() {
      const unsynced = app.items.filter(i => !i.synced);
      const synced = app.items.filter(i => i.synced);
      const newPhotos = unsynced.filter(i => i.category === 'photo').length;
      const newVideos = unsynced.filter(i => i.category === 'video').length;
      const newRaw = unsynced.filter(i => i.category === 'raw').length;
      const totalSynced = (app.serverTotalSynced || 0) + synced.length;
      const deltaMB = unsynced.reduce((sum, i) => sum + i.sizeMB, 0);
      const watermark = app.serverWatermark || 'Live';

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

    function switchIosTab(tab) {
      app.iosTab = tab;
      ['home', 'photos', 'queue'].forEach(t => {
        const screen = document.getElementById(`ios-screen-${t}`);
        const navBtn = document.getElementById(`ios-nav-${t}`);
        if (screen) {
          if (t === tab) screen.classList.remove('hidden');
          else screen.classList.add('hidden');
        }
        if (navBtn) {
          if (t === tab) {
            navBtn.className = 'w-10 h-10 rounded-full bg-white text-zinc-900 flex items-center justify-center transition-all shadow-xs';
          } else {
            navBtn.className = 'w-10 h-10 rounded-full text-white/70 hover:text-white flex items-center justify-center transition-all';
          }
        }
      });
      renderAll();
    }

    function setPhotoFilter(filter) {
      app.photoFilter = filter;
      renderIosPhotosScreen();
    }

    function togglePhotoSelect(id) {
      const item = app.items.find(i => i.id === id);
      if (!item || item.synced) return;
      item.selected = !item.selected;
      renderIosPhotosScreen();
    }

    function toggleSelectAllUnsynced() {
      const unsynced = app.items.filter(i => !i.synced);
      const allSelected = unsynced.length > 0 && unsynced.every(i => i.selected);
      unsynced.forEach(i => { i.selected = !allSelected; });
      renderIosPhotosScreen();
    }

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
      if (app.isSyncing) pauseTransfer();
      else resumeTransfer();
    }

    function triggerOneTapSync() {
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

    function syncSelectedPhotos() {
      const selected = app.items.filter(i => !i.synced && i.selected);
      if (selected.length === 0) return;
      switchIosTab('queue');
      app.isPaused = false;
      app.isSyncing = true;
      startRealtimeSyncLoop( true );
    }

    function handleFilesSelected(files) {
      if (!files || !files.length) return;
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
      checkServerDuplicates(added);
    }

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
      pollServerStatus();
      setInterval(pollServerStatus, 3000);
      renderAll();
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
            xhr.onerror = () => { activeXhr = null; reject(new Error('Connection dropped')); };
            xhr.ontimeout = () => { activeXhr = null; reject(new Error('Upload timeout')); };
            xhr.onabort = () => { activeXhr = null; reject(new Error('Transfer paused')); };
            xhr.timeout = 180000;
            xhr.open('POST', url);
            if (sid) {
              try { xhr.setRequestHeader('X-PD-Session', sid); } catch (_) {}
            }
            xhr.send(item.file);
          });
          return;
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
            const hdr = document.getElementById('ios-header-status');
            if (hdr) hdr.textContent = `Samsung Galaxy • ${app.freeGB.toFixed(0)} GB Free`;
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
          }
          if (syncData.total_synced !== undefined) {
            app.serverTotalSynced = syncData.total_synced;
            const bubbleSynced = document.getElementById('bubble-synced-sub');
            if (bubbleSynced) bubbleSynced.textContent = syncData.total_synced.toLocaleString();
          }
        }
      } catch (_) {}
    }

    async function startRealtimeSyncLoop(selectedOnly = false) {
      let wakeLock = null;
      try {
        if ('wakeLock' in navigator) wakeLock = await navigator.wakeLock.request('screen');
      } catch (_) {}

      let sid = window._pd_sid || "";
      if (!sid) {
        try { sid = sessionStorage.getItem("pd_sid") || ""; } catch (_) {}
      }

      renderAll();

      while (app.isSyncing && !app.isPaused) {
        const remaining = app.items.filter(i => !i.synced && (!selectedOnly || i.selected));
        if (remaining.length === 0) {
          app.isSyncing = false;
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
          } catch (err) {
            if (app.isPaused) {
              current.progress = 0;
              break;
            }
            current.err = true;
            current.errMessage = err.message || 'Failed';
            app.isSyncing = false;
            renderAll();
            break;
          }
        }

        renderAll();
        pollServerStatus();
      }

      if (wakeLock) {
        try { await wakeLock.release(); } catch (_) {}
      }
    }

    function renderIosHome(stats) {
      document.getElementById('bubble-photos-sub').textContent = stats.newPhotos > 0 ? `${stats.newPhotos} New` : '0 New';
      document.getElementById('bubble-videos-sub').textContent = stats.newVideos > 0 ? `${stats.newVideos} New` : '0 New';
      document.getElementById('bubble-raw-sub').textContent = stats.newRaw > 0 ? `${stats.newRaw} New` : '0 New';
      document.getElementById('bubble-synced-sub').textContent = stats.totalSynced.toLocaleString();

      const connector = document.getElementById('ios-connector-pill');
      const heroTitle = document.getElementById('ios-hero-title');
      const heroDesc = document.getElementById('ios-hero-desc');
      const heroCtaText = document.getElementById('ios-hero-cta-text');
      const heroSpeed = document.getElementById('ios-hero-speed');

      if (app.isPaused) {
        connector.textContent = `Transfer Paused • ${stats.unsyncedCount} Remaining`;
        heroTitle.textContent = 'Transfer Paused';
        heroDesc.textContent = `Tap below to resume streaming ${stats.unsyncedCount} items (${stats.deltaMB} MB) to Samsung Galaxy.`;
        heroCtaText.textContent = `▶ Resume Backing Up (${stats.unsyncedCount} Left)`;
        heroSpeed.classList.add('hidden');
        return;
      }

      if (app.isSyncing) {
        connector.textContent = `Streaming ${stats.unsyncedCount} Left • ${stats.deltaMB} MB`;
        heroTitle.textContent = `Streaming (${stats.unsyncedCount} Left)...`;
        heroDesc.textContent = `Transferring directly to Samsung Galaxy in original quality.`;
        heroCtaText.textContent = '⏸ Pause Transfer';
        heroSpeed.classList.remove('hidden');
      } else if (stats.unsyncedCount === 0) {
        if (app.items.length === 0) {
          connector.textContent = `Ready to Sync • Direct to Samsung`;
          heroTitle.textContent = 'Add Photos to Back Up';
          heroDesc.textContent = 'Pick photos, videos, or ProRAW from your iPhone to stream directly to Samsung Galaxy.';
          heroCtaText.textContent = 'Select Photos & Videos Now';
        } else {
          connector.textContent = `All ${stats.totalSynced.toLocaleString()} Backed Up Cleanly`;
          heroTitle.textContent = 'All Caught Up!';
          heroDesc.textContent = `Every photo & video is safely stored in DCIM/PhotoDrop on Samsung.`;
          heroCtaText.textContent = '+ Add More Photos';
        }
        heroSpeed.classList.add('hidden');
      } else {
        connector.textContent = `${stats.unsyncedCount} Unsynced Items • ${stats.deltaMB} MB Delta`;
        heroTitle.textContent = `${stats.unsyncedCount} New Photos Waiting`;
        heroDesc.textContent = `Ready to stream to Samsung Galaxy (${stats.deltaMB} MB total).`;
        heroCtaText.textContent = `Back Up ${stats.unsyncedCount} Items Now`;
        heroSpeed.classList.add('hidden');
      }
    }

    function renderIosPhotosScreen() {
      const stats = getDeltaStats();
      const btnUnsynced = document.getElementById('seg-btn-unsynced');
      const btnAll = document.getElementById('seg-btn-all');

      if (btnUnsynced) btnUnsynced.textContent = `Unsynced (${stats.unsyncedCount})`;
      if (btnAll) btnAll.textContent = `All Library (${app.items.length})`;

      if (app.photoFilter === 'unsynced') {
        if (btnUnsynced) btnUnsynced.className = 'py-2.5 rounded-full text-xs font-bold bg-electric text-white shadow-xs transition-all tabular-nums';
        if (btnAll) btnAll.className = 'py-2.5 rounded-full text-xs font-bold bg-white text-zinc-700 hover:bg-zinc-100 transition-all tabular-nums';
      } else {
        if (btnAll) btnAll.className = 'py-2.5 rounded-full text-xs font-bold bg-electric text-white shadow-xs transition-all tabular-nums';
        if (btnUnsynced) btnUnsynced.className = 'py-2.5 rounded-full text-xs font-bold bg-white text-zinc-700 hover:bg-zinc-100 transition-all tabular-nums';
      }

      const list = app.photoFilter === 'unsynced'
        ? app.items.filter(i => !i.synced)
        : app.items.slice().reverse();

      const grid = document.getElementById('ios-photo-grid');
      if (!grid) return;

      if (list.length === 0) {
        grid.innerHTML = `
          <div class="col-span-2 bg-white rounded-[24px] p-8 text-center shadow-soft">
            <div class="w-10 h-10 rounded-full bg-emerald-100 text-emerald-700 mx-auto flex items-center justify-center mb-2">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg>
            </div>
            <div class="text-xs font-extrabold text-zinc-900">Zero Unsynced Photos</div>
            <p class="text-[11px] text-zinc-500 mt-0.5">Tap "+ Add" above to pick photos from your camera roll.</p>
          </div>
        `;
      } else {
        grid.innerHTML = list.slice(0, 300).map(item => {
          const isSelected = item.selected && !item.synced;
          return `
            <div onclick="togglePhotoSelect('${item.id}')" class="group cursor-pointer">
              <div class="relative aspect-square rounded-[22px] overflow-hidden bg-zinc-200 shadow-xs border-2 transition-all ${
                isSelected ? 'border-electric scale-[0.98]' : 'border-transparent'
              } ${item.synced ? 'opacity-65' : ''}">
                ${item.url ? `
                  <img src="${item.url}" alt="${item.title}" loading="lazy" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300" />
                ` : `
                  <div class="w-full h-full bg-zinc-100 flex items-center justify-center font-bold text-xs text-zinc-500">${item.category.toUpperCase()}</div>
                `}
                <div class="absolute top-2.5 right-2.5">
                  ${item.synced ? `
                    <span class="px-2.5 py-0.5 rounded-full bg-emerald-500/90 backdrop-blur-xs text-white text-[10px] font-bold shadow-xs">Synced ✓</span>
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

      if (btn && label && mbSpan) {
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
    }

    function renderIosQueueScreen(stats) {
      const container = document.getElementById('ios-upload-queue-list');
      const badge = document.getElementById('ios-queue-count-badge');
      if (!container) return;

      if (badge) badge.textContent = stats.unsyncedCount > 0 ? `${stats.unsyncedCount} remaining` : 'All Complete';

      const totalItems = app.items.length;
      const syncedItems = app.items.filter(i => i.synced).length;
      const totalMB = app.items.reduce((s, i) => s + i.sizeMB, 0).toFixed(1);
      const syncedMB = app.items.filter(i => i.synced).reduce((s, i) => s + i.sizeMB, 0).toFixed(1);
      const overallPct = totalItems > 0 ? Math.round((syncedItems / totalItems) * 100) : 0;

      const batchCardHtml = `
        <div class="bg-white rounded-[24px] p-4 shadow-soft space-y-2.5 mb-3">
          <div class="flex items-center justify-between text-xs font-extrabold text-zinc-900">
            <span>Overall Queue (${syncedItems} of ${totalItems} synced)</span>
            <span class="font-mono text-electric tabular-nums">${overallPct}% · ${syncedMB}/${totalMB} MB</span>
          </div>
          <div class="w-full h-2 rounded-full bg-zinc-100 overflow-hidden">
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
        const pct = item.synced ? 100 : (item.progress || (idx === 0 && app.isSyncing ? 80 : 0));
        let itemStatus = 'Waiting';
        if (item.synced) itemStatus = 'Saved to Samsung Galaxy';
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
        } catch (err) {
          item.err = true;
          item.errMessage = err.message || 'Failed';
          alert('Upload failed: ' + (err.message || 'Check connection'));
        }
      }
      renderAll();
    }

    function renderAll() {
      const stats = getDeltaStats();
      renderIosHome(stats);
      renderIosPhotosScreen();
      renderIosQueueScreen(stats);
    }
  </script>
</body>
</html>
"""

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
