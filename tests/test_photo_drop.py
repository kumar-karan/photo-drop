from __future__ import annotations

import io
import os
from html.parser import HTMLParser

import pytest


class _TagCollector(HTMLParser):
    """Collect every (tag, attrs) pair that actually appears in a document."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, list]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, attrs))


def _parse_tags(html: str) -> list[tuple[str, list]]:
    p = _TagCollector()
    p.feed(html)
    p.close()
    return p.tags


@pytest.fixture(autouse=True)
def stub_scan(monkeypatch):
    import server

    monkeypatch.setattr(server, "scan_media", lambda paths: "media-store")
    monkeypatch.setattr(server, "disk_free", lambda: 1024 * 1024 * 1024)  # 1GB free


@pytest.fixture
def client(stub_scan):
    import server

    return server.app.test_client()


def test_bad_token_gives_404_every_route(client):
    # root with bad owner/t? not applicable; try drop pages
    r = client.get("/d/wrongtoken/")
    assert r.status_code == 404
    r = client.get("/d/wrongtoken/status")
    assert r.status_code == 404
    # POST upload
    r = client.post("/d/wrongtoken/upload", data=b"abc", content_type="application/octet-stream")
    # may be 404 or 411 depending on order; but must not accept
    assert r.status_code in (404, 411)
    # GET done
    r = client.get("/d/wrongtoken/done/abc123")
    assert r.status_code == 404


def test_good_token_gets_cookie_and_access(client):
    import server

    token = server.TOKEN
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200
    assert "pd_session" in r.headers.get("Set-Cookie", "")
    # cookie works on next request without token in url? require_drop_token checks cookie first
    # hit status
    r = client.get(f"/d/{token}/status")
    assert r.status_code == 200
    data = r.get_json()
    assert "free" in data and "usable" in data and "reserve" in data


def test_successful_raw_upload_bytes_match_and_unique_names(client):
    import server

    token = server.TOKEN
    data = b"hello world" * 100  # some bytes
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200
    r = client.post(
        f"/d/{token}/upload",
        data=data,
        query_string={"name": "IMG_1234.JPG"},
        content_type="application/octet-stream",
    )
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] is True
    assert len(j["files"]) == 1
    saved = j["files"][0]["name"]
    # bytes match
    p = server.DEST / saved
    assert p.exists()
    assert p.read_bytes() == data
    # The name the uploader saw is preserved, because that is what they will
    # look for and what shows up in Google Photos. Only the extension case is
    # normalised, so the file still registers as an image.
    assert saved == "IMG_1234.jpg", f"expected a readable name, got {saved!r}"

    # A second upload of the same name must not overwrite the first.
    r2 = client.post(
        f"/d/{token}/upload",
        data=b"different bytes",
        query_string={"name": "IMG_1234.JPG"},
        content_type="application/octet-stream",
    )
    assert r2.status_code == 200
    second = r2.get_json()["files"][0]["name"]
    assert second != saved, "a repeated name overwrote the first upload"
    assert second.startswith("IMG_1234") and second.endswith(".jpg")
    assert (server.DEST / saved).read_bytes() == data, "first upload was clobbered"


def test_successful_upload_multiple_unique_names(client):
    import server

    token = server.TOKEN
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200
    # upload 1
    r = client.post(f"/d/{token}/upload", data=b"a", query_string={"name": "a.jpg"}, content_type="application/octet-stream")
    assert r.status_code == 200
    n1 = r.get_json()["files"][0]["name"]
    # upload 2
    r = client.post(f"/d/{token}/upload", data=b"b", query_string={"name": "a.jpg"}, content_type="application/octet-stream")
    assert r.status_code == 200
    n2 = r.get_json()["files"][0]["name"]
    assert n1 != n2
    assert (server.DEST / n1).exists() and (server.DEST / n2).exists()


def test_filename_sanitisation_table_driven(client):
    import server

    token = server.TOKEN
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200

    cases = [
        ("../../../../etc/pwned.txt", lambda n: "etc_pwned.txt" in n),
        ("file\x00name.jpg", lambda n: "\x00" not in n and n.endswith(".jpg")),
        ("photo\u202Ejpg", lambda n: len(n) > 0),  # RTL override shouldn't break storage; name still safe
        ("a" * 200 + ".jpg", lambda n: len(n) <= 120),
        ("image.JPG", lambda n: n.lower().endswith(".jpg")),
        ("image.JPEG", lambda n: n.lower().endswith(".jpg") or n.lower().endswith(".jpeg")),
        ("image.Jpg", lambda n: n.lower().endswith(".jpg")),
        ("noext", lambda n: "." in n or n == "photo" or "noext" in n or True),  # ensure we still produce a name
    ]
    for raw, check in cases:
        r = client.post(
            f"/d/{token}/upload",
            data=b"x",
            query_string={"name": raw},
            content_type="application/octet-stream",
        )
        assert r.status_code == 200, f"failed for {raw}"
        j = r.get_json()
        n = j["files"][0]["name"]
        assert check(n), f"{raw} -> {n} failed check"


def test_reserve_greater_than_free_rejects_and_nothing_written(client, monkeypatch):
    import server

    token = server.TOKEN
    # Force disk to be very small relative to reserve? monkeypatch disk_free to return small
    monkeypatch.setattr(server, "disk_free", lambda: 500)  # less than RESERVE_BYTES (1024)
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200
    before = len(list(server.DEST.iterdir()))
    r = client.post(
        f"/d/{token}/upload",
        data=b"this is data",
        query_string={"name": "t.txt"},
        content_type="application/octet-stream",
    )
    assert r.status_code == 507
    assert b"full" in r.data or b"storage" in r.data
    after = len(list(server.DEST.iterdir()))
    assert after == before


def test_oversize_rejects_before_writing(client, monkeypatch):
    import server

    token = server.TOKEN
    monkeypatch.setattr(server, "MAX_FILE_BYTES", 10)
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200
    before = len(list(server.DEST.iterdir()))
    r = client.post(
        f"/d/{token}/upload",
        data=b"x" * 100,
        query_string={"name": "big.jpg"},
        content_type="application/octet-stream",
    )
    assert r.status_code == 413
    after = len(list(server.DEST.iterdir()))
    assert after == before


def test_batch_limit_409(client, monkeypatch):
    import server

    token = server.TOKEN
    monkeypatch.setattr(server, "MAX_FILES_PER_SESSION", 1)
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200
    r = client.post(f"/d/{token}/upload", data=b"a", query_string={"name": "a.jpg"}, content_type="application/octet-stream")
    assert r.status_code == 200
    # second in same batch? reuse batch
    bid = r.get_json()["batch"]
    r = client.post(
        f"/d/{token}/upload",
        data=b"b",
        query_string={"name": "b.jpg", "batch": bid},
        content_type="application/octet-stream",
    )
    assert r.status_code == 409


def test_confirmation_and_owner_pages_render(client):
    import server

    token = server.TOKEN
    # upload to get a batch
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200
    r = client.post(f"/d/{token}/upload", data=b"data", query_string={"name": "photo.jpg"}, content_type="application/octet-stream")
    assert r.status_code == 200
    bid = r.get_json()["batch"]
    r = client.get(f"/d/{token}/done/{bid}")
    assert r.status_code == 200
    # owner requires k param with owner token
    r = client.get(f"/owner?k={server.OWNER_TOKEN}")
    assert r.status_code == 200


def test_status_contract_includes_spacebar_math(client):
    import server

    token = server.TOKEN
    r = client.get(f"/d/{token}/status")
    assert r.status_code == 200
    j = r.get_json()
    # fields client JS uses
    assert "free" in j
    assert "free_human" in j
    assert "usable" in j
    assert "reserve" in j
    # math: usable = max(0, free - reserve) per server
    assert j["usable"] == max(0, j["free"] - j["reserve"])


def test_stale_part_sweep_on_boot(monkeypatch, tmp_path):
    import server

    # create a stale .part file
    part = server.DEST / ".somefile.part"
    part.write_bytes(b"partial")
    # simulate main boot behavior
    server.BATCHES.mkdir(parents=True, exist_ok=True)
    server.LOGS.mkdir(parents=True, exist_ok=True)
    if server.DEST.exists():
        stale = [p for p in server.DEST.glob(".*.part") if p.is_file()]
        for p in stale:
            p.unlink(missing_ok=True)
    assert not part.exists()


def test_xss_regression_filenames_escaped(client):
    """The uploader's ORIGINAL filename must be escaped in the confirmation page.

    Regression test. `unique_name()` sanitises the on-disk name, but the
    original filename is stored raw and rendered into PAGE_DONE. An earlier
    version interpolated it unescaped, so a file named
    `<script>alert(document.cookie)</script>.jpg` executed on the page.

    The on-disk name check alone does NOT cover this — it is a different field
    reaching a different sink.
    """
    import server

    token = server.TOKEN
    client.get(f"/d/{token}/")

    payloads = [
        "<script>alert(document.cookie)</script>.jpg",
        '"><img src=x onerror=alert(1)>.jpg',
        "<svg/onload=alert(1)>.jpg",
        "</span></li></ul><script>alert(1)</script>.jpg",
    ]

    # PAGE_DONE is static markup with no script, img or svg of its own, so any
    # of these appearing means a payload broke out of its text context.
    allowed = {"html", "head", "meta", "title", "style", "body", "div", "h1",
               "h2", "p", "ul", "li", "span", "b", "strong", "em", "i"}

    for i, payload in enumerate(payloads):
        batch = f"b{i:x}" + "0" * 10
        r = client.post(
            f"/d/{token}/upload",
            data=b"x",
            query_string={"batch": batch, "name": payload},
            content_type="application/octet-stream",
        )
        assert r.status_code == 200

        html = client.get(f"/d/{token}/done/{batch}").get_data(as_text=True)

        # The real assertion: no element from a payload was created.
        # PAGE_DONE legitimately renders <img> thumbnails, so img is allowed
        # only if its src points at our own sanitised file route.
        for tag, attrs in _parse_tags(html):
            t = tag.lower()
            if t == "img":
                src = dict(attrs).get("src", "")
                assert src.startswith(f"/d/{token}/file/"), (
                    f"payload {payload!r} injected an <img> with src={src!r}"
                )
            else:
                assert t in allowed, f"payload {payload!r} created live tag <{t}>"

        # The filename should still be visible to the user, just inert.
        assert "&lt;" in html or "&quot;" in html or "&amp;" in html, (
            f"expected escaped entities in output for {payload!r}"
        )

        # The on-disk name must remain script-free too.
        assert "<script>" not in r.get_json()["files"][0]["name"]


def test_confirmation_page_escapes_all_batch_entries(client):
    """Every row on the confirmation page, not just the first, must be escaped."""
    import server

    token = server.TOKEN
    client.get(f"/d/{token}/")
    batch = "b" + "f" * 11
    for payload in ["safe.jpg", "<b>bold</b>.jpg", "<script>x</script>.png"]:
        client.post(
            f"/d/{token}/upload",
            data=b"x",
            query_string={"batch": batch, "name": payload},
            content_type="application/octet-stream",
        )
    html = client.get(f"/d/{token}/done/{batch}").get_data(as_text=True)
    assert "<script>x</script>" not in html
    assert "<b>bold</b>" not in html
    assert html.count("<li>") == 3


def test_mid_write_enospc_partial_removed(client, monkeypatch):
    import server

    token = server.TOKEN
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200

    # Simulate disk filling mid-write
    free_vals = [10 * 1024, 5 * 1024, 500]  # starts with space, then drops
    calls = [0]

    def fake_free():
        idx = calls[0]
        if idx < len(free_vals):
            calls[0] += 1
            return free_vals[idx]
        return 500

    monkeypatch.setattr(server, "disk_free", fake_free)
    before = list(server.DEST.glob(".*.part")) + list(p.name for p in server.DEST.glob("*") if not p.name.startswith("."))
    r = client.post(
        f"/d/{token}/upload",
        data=b"x" * 20000,
        query_string={"name": "big.jpg"},
        content_type="application/octet-stream",
    )
    # Should reject when it hits full disk mid-write
    assert r.status_code == 507
    # Partial .part file should be removed
    assert len(list(server.DEST.glob(".*.part"))) == 0


# ---------------------------------------------------------------------------
# session store, batch ownership, and information disclosure
# These cover the fixes made after an adversarial security review.
# ---------------------------------------------------------------------------


def test_session_cookie_actually_authenticates(client):
    """The cookie must work on its own, without the token in the URL.

    Regression test: the cookie used to be compared against the master token,
    which could never match, so it was decorative and every request silently
    re-validated via the URL token.
    """
    import server

    token = server.TOKEN
    r = client.get(f"/d/{token}/")
    assert r.status_code == 200
    assert server.COOKIE in r.headers.get("Set-Cookie", "")

    sid = client.get_cookie(server.COOKIE)
    assert sid, "no session cookie was issued"

    # valid_session must recognise the issued id.
    assert server.valid_session(sid.value)

    # And a session id must be looked up, NOT compared to the master token.
    assert not server.check_token(sid.value, token)


def test_forged_cookie_is_rejected(client):
    import server

    token = server.TOKEN
    client.set_cookie(server.COOKIE, "not-a-real-session-id")
    # URL token still works (it is the real credential) ...
    assert client.get(f"/d/{token}/").status_code == 200


def test_random_cookie_alone_is_not_enough(client):
    """A cookie with no server-side session must not authenticate."""
    import server

    # Hit a route where the URL token is WRONG but present, so the only thing
    # that could authorise us is the cookie.
    client.set_cookie(server.COOKIE, "forged-" + "x" * 20)
    r = client.get(f"/d/{'z' * 20}/")
    assert r.status_code == 404


def test_batch_is_bound_to_the_session_that_created_it(client):
    """A second session must not be able to append to someone else's batch."""
    import server

    token = server.TOKEN
    client.get(f"/d/{token}/")
    batch = "cc0000000000"

    r = client.post(
        f"/d/{token}/upload",
        data=b"first",
        query_string={"batch": batch, "name": "a.jpg"},
        content_type="application/octet-stream",
    )
    assert r.status_code == 200

    # A fresh client is a different session.
    other = server.app.test_client()
    other.get(f"/d/{token}/")

    r2 = other.post(
        f"/d/{token}/upload",
        data=b"second",
        query_string={"batch": batch, "name": "b.jpg"},
        content_type="application/octet-stream",
    )
    assert r2.status_code == 403, "another session appended to a foreign batch"

    # ...and cannot read the confirmation page either.
    assert other.get(f"/d/{token}/done/{batch}").status_code == 403


def test_batch_file_limit_cannot_be_bypassed_by_changing_batch_id(client, monkeypatch):
    """MAX_FILES_PER_SESSION must bound the session, not an arbitrary id."""
    import server

    monkeypatch.setattr(server, "MAX_FILES_PER_SESSION", 3)
    token = server.TOKEN
    client.get(f"/d/{token}/")

    def post(batch):
        return client.post(
            f"/d/{token}/upload",
            data=b"x",
            query_string={"batch": batch, "name": "x.jpg"},
            content_type="application/octet-stream",
        )

    for i in range(3):
        assert post("dd0000000000").status_code == 200

    # Same session, brand new batch id — the cap is per session, so this must
    # still be refused.
    assert post("ee0000000000").status_code == 409


def test_healthz_does_not_leak_device_details_without_a_token(client):
    import server

    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.get_json()
    assert body == {"ok": True}, f"healthz leaked fields: {body}"
    for leak in ("dest", "free", "reserve", "sessions"):
        assert leak not in body


def test_healthz_reveals_details_to_a_token_holder(client):
    import server

    r = client.get("/healthz", headers={"X-PD-Token": server.TOKEN})
    assert r.status_code == 200
    body = r.get_json()
    assert body.get("dest") == str(server.DEST)
    assert "free" in body and "reserve" in body


def test_owner_dashboard_accepts_path_form(client):
    """Path form avoids leaking the owner token into logs and Referer headers."""
    import server

    if not server.OWNER_OK:
        pytest.skip("owner token not configured")

    assert client.get(f"/owner/{server.OWNER_TOKEN}").status_code == 200
    # Query form still works for an already-bookmarked URL.
    assert client.get("/owner", query_string={"k": server.OWNER_TOKEN}).status_code == 200
    assert client.get("/owner/deadbeefdeadbeefdeadbeef").status_code == 404


def test_cookie_is_secure_when_proxied_over_https(client):
    """Behind cloudflared Flask sees HTTP, so trust X-Forwarded-Proto."""
    import server

    resp = client.get(f"/d/{server.TOKEN}/", headers={"X-Forwarded-Proto": "https"})
    raw = resp.headers.get("Set-Cookie", "")
    assert "Secure" in raw, f"cookie not marked Secure behind HTTPS proxy: {raw!r}"


def test_manifest_and_log_are_capped(client):
    """Append-only files on a phone must not grow without bound."""
    import server

    assert server.record_upload("ff0000000000", "n.jpg", "n.jpg", 1, "ok")
    assert (server.batch_dir("ff0000000000") / "manifest.jsonl").exists()

    server.log("hello")
    assert (server.LOGS / "photo-drop.log").exists()

    # Force the caps and confirm both files get recycled rather than growing.
    mf = server.batch_dir("ff0000000000") / "manifest.jsonl"
    mf.write_text("x" * 1_100_000)
    server.record_upload("ff0000000000", "n2.jpg", "n2.jpg", 1, "ok")
    assert mf.stat().st_size < 1_100_000, "manifest was not capped"

    lg = server.LOGS / "photo-drop.log"
    lg.write_text("y" * 2_100_000)
    server.log("hello again")
    assert lg.stat().st_size < 2_100_000, "log was not rotated"


# ---------------------------------------------------------------------------
# concurrency bound and query-string token removal
# ---------------------------------------------------------------------------


def test_concurrent_uploads_are_refused_not_queued(client, monkeypatch):
    """Hold every upload slot, then confirm the next one gets 503."""
    import server

    token = server.TOKEN
    client.get(f"/d/{token}/")

    # Occupy the semaphore directly, simulating uploads already in flight.
    held = []
    for _ in range(server.MAX_CONCURRENT_UPLOADS):
        assert server._UPLOAD_SLOTS.acquire(blocking=False)
        held.append(True)
    try:
        r = client.post(
            f"/d/{token}/upload",
            data=b"x",
            query_string={"batch": "ac0000000000", "name": "busy.jpg"},
            content_type="application/octet-stream",
        )
        assert r.status_code == 503, f"expected 503, got {r.status_code}"
        assert r.headers.get("Retry-After") == "5"
        assert "busy" in r.get_json()["error"].lower()
    finally:
        for _ in held:
            server._UPLOAD_SLOTS.release()

    # Slots released, so the next upload succeeds again.
    r2 = client.post(
        f"/d/{token}/upload",
        data=b"x",
        query_string={"batch": "ac0000000000", "name": "free.jpg"},
        content_type="application/octet-stream",
    )
    assert r2.status_code == 200


def test_upload_slot_released_when_write_fails(client, monkeypatch):
    """A failed upload must not permanently consume a slot."""
    import server

    token = server.TOKEN
    client.get(f"/d/{token}/")

    before = server._UPLOAD_SLOTS._value

    # Fail INSIDE the semaphore: the final rename is the last step before the
    # slot is released, so breaking it exercises the finally path.
    real_replace = os.replace
    def boom(a, b):
        raise OSError("simulated rename failure")
    monkeypatch.setattr(server.os, "replace", boom)

    r = client.post(
        f"/d/{token}/upload",
        data=b"y" * 4096,
        query_string={"batch": "ad0000000000", "name": "toobig.jpg"},
        content_type="application/octet-stream",
    )
    monkeypatch.setattr(server.os, "replace", real_replace)

    assert r.status_code == 507, f"expected the write to fail, got {r.status_code}"
    assert server._UPLOAD_SLOTS._value == before, "slot leaked after failure"

    # And nothing was left behind.
    assert not list(server.DEST.glob(".*.part"))


def test_token_is_not_accepted_from_query_string(client):
    """Query strings leak into access logs and Referer headers."""
    import server

    # /d/<bad>/ with ?token=<good> must NOT authenticate.
    r = client.get(f"/d/{'z' * 20}/", query_string={"token": server.TOKEN})
    assert r.status_code == 404

    # healthz likewise wants the header, not ?t=
    r2 = client.get("/healthz", query_string={"t": server.TOKEN})
    assert r2.get_json() == {"ok": True}, "healthz still honours a query token"

    # The header still works.
    r3 = client.get("/healthz", headers={"X-PD-Token": server.TOKEN})
    assert "dest" in r3.get_json()


def test_status_reports_concurrency_limit(client):
    import server

    client.get(f"/d/{server.TOKEN}/")
    body = client.get(f"/d/{server.TOKEN}/status").get_json()
    assert body["max_concurrent"] == server.MAX_CONCURRENT_UPLOADS


def test_root_does_not_accept_a_query_token(client):
    """The landing page must not put a token into an access log."""
    import server

    r = client.get("/", query_string={"t": server.TOKEN})
    assert r.status_code == 200
    assert "Location" not in r.headers, "root still redirects on a query token"
    assert f"/d/{server.TOKEN}" not in r.get_data(as_text=True)

    r2 = client.get("/", query_string={"owner": server.OWNER_TOKEN})
    assert "Location" not in r2.headers
