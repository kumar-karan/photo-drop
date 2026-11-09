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
MAX_FILES_PER_SESSION = int(os.environ.get("PHOTO_DROP_MAX_FILES", "500"))

# Concurrent uploads allowed at once. Flask's dev server spawns a thread per
# request, so without this a client could open hundreds of simultaneous
# multi-gigabyte writes and exhaust RAM, file descriptors or the disk write
# queue. Uploads are refused with 503 rather than queued, so a phone never
# silently builds a backlog it cannot drain.
MAX_CONCURRENT_UPLOADS = int(os.environ.get("PHOTO_DROP_MAX_CONCURRENT", "3"))
_UPLOAD_SLOTS = threading.BoundedSemaphore(max(1, MAX_CONCURRENT_UPLOADS))

# How long a session cookie stays valid.
SESSION_TTL = int(os.environ.get("PHOTO_DROP_SESSION_TTL", str(12 * 3600)))

APP_VERSION = "1.6.0"
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
    """
    sid = session_id()
    if session_valid(sid):
        note_session(sid)
        return sid, False

    candidate = request.view_args.get("token", "") if request.view_args else ""
    if not candidate:
        candidate = request.headers.get("X-PD-Token", "")
    if candidate and check_token(candidate, TOKEN):
        sid = new_session()
        register_session(sid)
        note_session(sid)
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
# live sessions
# --------------------------------------------------------------------------


def _new_session_record(sid: str, now: float) -> dict:
    return {
        "sid": sid,
        "created": now,
        "last_seen": now,
        "last_at": 0.0,
        "ip": "",
        "label": "Browser",
        "batches": set(),
        "files": 0,
        "bytes": 0,
        "recent_files": [],
        "last_file": "",
        "active": [],
        "connected": False,
    }


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

    sessions = []
    for record in records.values():
        if not (record["connected"] or record["files"] or record["active"]):
            continue
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
        })

    def sort_key(s: dict):
        if s["state"] == "uploading":
            return (0, s["last_seen_age"])
        if s["state"] == "recent":
            return (1, s["last_seen_age"])
        if s["state"] == "connected":
            return (2, s["last_seen_age"])
        return (3, s["last_seen_age"])

    sessions.sort(key=sort_key)
    return sessions


def build_owner_state() -> dict:
    now = time.time()
    all_sessions = collect_sessions(now)
    # The console is polled about once a second; 20 cards is plenty to look at
    # and keeps the payload small during a party. Totals still cover everyone.
    sessions = all_sessions[:20]
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
            "sessions": len(all_sessions),
            "shown_sessions": len(sessions),
            "uploading_sessions": len({s["id"] for s in all_sessions if s["state"] == "uploading"}),
            "connected_sessions": len([s for s in all_sessions if s["connected"]]),
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
        return jsonify(
            ok=True,
            version=APP_VERSION,
            uptime=_age(STARTED_AT),
            dest=str(DEST),
            free=free,
            dest_size=total,
            used=max(0, total - free),
            reserve=RESERVE_BYTES,
            sessions=len(sessions),
            total_sessions=len(sessions),
            active_sessions=len([s for s in sessions if s["state"] in {"uploading", "recent"}]),
            public_url=get_public_url(),
            lan_ip=get_lan_ip(),
            upload_stats=stats,
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
    resp = make_response(PAGE_UPLOAD.format(
        reserve=human(RESERVE_BYTES),
        max_mb=MAX_FILE_BYTES // (1024 * 1024),
        base=f"/d/{TOKEN}",
    ))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    if is_new:
        set_session_cookie(resp, sid)
    return resp


@app.get("/d/<token>/status")
def drop_status(token: str):
    sid, _ = require_drop_token()
    free = disk_free()
    bid = request.args.get("batch") or ""
    mine = bool(re.fullmatch(r"[a-f0-9]{6,32}", bid or "")) and batch_owned_by(bid, sid)
    with _ACTIVE_LOCK:
        active = [t for t in _ACTIVE_TRANSFERS.values() if t["sid"] == sid]
    return jsonify(
        free=free,
        free_human=human(free),
        usable=max(0, free - RESERVE_BYTES),
        uploaded=batch_count(bid) if mine else 0,
        session_files=session_file_count(sid),
        receiving=len(active),
        receiving_files=[t["name"] for t in active],
        session=sid[:6],
        reserve=RESERVE_BYTES,
        max_concurrent=MAX_CONCURRENT_UPLOADS,
        max_files=MAX_FILES_PER_SESSION,
        version=APP_VERSION,
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

        # Hand the file to MediaProvider so Google Photos sees it.
        scanned = scan_media([str(target)])
        record_upload(bid, name, original, written, scanned)
        saved = True
        log(f"saved {original} -> {name} ({written}B, scan={scanned})")
    finally:
        finish_transfer(transfer_id, saved)
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
    return '<article class="session state-' + esc(s.state) + '">'
      + '<div class="s-top">'
      + '<div class="avatar" aria-hidden="true">' + esc(initial) + '</div>'
      + '<div class="s-id"><div class="s-name">' + esc(s.label || "Browser") + '</div>'
      + '<div class="s-meta">Guest ' + esc(s.id) + ' · ' + esc(s.ip || "unknown IP") + '</div></div>'
      + '<span class="pill ' + esc(s.state) + '">' + esc(stateLabel(s.state)) + '</span>'
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
    document.getElementById("statConnected").textContent = (totals.connected_sessions || 0) + " connected";
    document.getElementById("statInflight").textContent = inFlight;
    document.getElementById("statUploading").textContent = uploading > 0
      ? uploading + (uploading === 1 ? " session" : " sessions")
      : "idle";
    document.getElementById("statFiles").textContent = totals.files || 0;
    document.getElementById("statBytes").textContent = totals.bytes_human || "0 B";

    var shownSessions = sessions.length;
    var totalSessions = Number(totals.sessions) || shownSessions;
    document.getElementById("sessionCount").textContent = shownSessions
      ? (shownSessions < totalSessions
          ? "showing " + shownSessions + " of " + totalSessions
          : shownSessions + (shownSessions === 1 ? " guest" : " guests"))
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
  .live-strip {{
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
    margin: -8px 2px 18px;
    color: var(--fg-muted);
    font-size: 11.5px;
  }}
  .live-dot {{
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 0 4px var(--accent-glow);
    animation: livePulse 2s ease-in-out infinite;
  }}
  @keyframes livePulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: .35; }}
  }}
  .live-label b {{
    color: var(--fg);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-weight: 600;
  }}
  .live-sep {{ color: var(--fg-subtle); }}
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

  <div class="live-strip">
    <span class="live-dot"></span>
    <span class="live-label">Live session <b id="sessionId">—</b></span>
    <span class="live-sep">·</span>
    <span id="sessionFiles">0 files received</span>
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
    document.getElementById("sessionId").textContent = d.session || "—";
    document.getElementById("sessionFiles").textContent =
      (d.session_files || 0) + ((d.session_files || 0) === 1 ? " file received" : " files received");
  }} catch (e) {{}}
}}
poll();
setInterval(poll, 3000);

window.addEventListener("beforeunload", e => {{
  if (!isUploading) return;
  e.preventDefault();
  e.returnValue = "";
}});

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
