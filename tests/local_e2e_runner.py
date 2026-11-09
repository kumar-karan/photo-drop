#!/usr/bin/env python3
"""
local_e2e_runner.py — Automated end-to-end integration test harness.

Spins up a real instance of server.py on local loopback and tests both sides:
  - iPhone PWA client (session cookie, status, multi-file uploads, duplicates, concurrency)
  - Samsung receiver (owner state telemetry, active transfers, storage math, recent list)
"""

import concurrent.futures
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

PORT = 8765
HOST = "127.0.0.1"
TOKEN = "test_drop_token_abc123"
OWNER_TOKEN = "test_owner_token_xyz789"
TMP_DIR = Path("/tmp/photodrop_local_test")
DEST_DIR = TMP_DIR / "DCIM" / "PhotoDrop"
HOME_DIR = TMP_DIR / "home"
EXPORT_DIR = TMP_DIR / "export"


def wait_for_port(host, port, timeout=5.0):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.05)
    return False


def make_request(url, method="GET", data=None, headers=None, cookie=None):
    hdrs = headers or {}
    if cookie:
        hdrs["Cookie"] = cookie
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            body = resp.read()
            resp_cookie = resp.headers.get("Set-Cookie", "")
            return resp.status, body, resp_cookie, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Set-Cookie", ""), dict(e.headers)


def main():
    print("=" * 60)
    print("Starting Photo Drop Dual-Sided Local E2E Test Suite")
    print("=" * 60)

    # 1. Clean and setup test directories
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR)
    DEST_DIR.mkdir(parents=True, exist_ok=True)
    HOME_DIR.mkdir(parents=True, exist_ok=True)
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["PHOTO_DROP_HOST"] = HOST
    env["PHOTO_DROP_PORT"] = str(PORT)
    env["PHOTO_DROP_TOKEN"] = TOKEN
    env["PHOTO_DROP_OWNER_TOKEN"] = OWNER_TOKEN
    env["PHOTO_DROP_DIR"] = str(DEST_DIR)
    env["PHOTO_DROP_HOME"] = str(HOME_DIR)
    env["PHOTO_DROP_EXPORT"] = str(EXPORT_DIR)
    env["PHOTO_DROP_RESERVE_BYTES"] = str(50 * 1024 * 1024)  # 50MB reserve
    env["PHOTO_DROP_ACQUIRE_TIMEOUT"] = "5.0"

    server_script = Path(__file__).resolve().parent.parent / "server.py"
    uv_bin = shutil.which("uv")
    if uv_bin:
        cmd = [uv_bin, "run", "--with", "flask", "python3", str(server_script)]
    else:
        cmd = [sys.executable, str(server_script)]

    server_proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        print("[1/6] Waiting for server to boot on port", PORT, "...")
        if not wait_for_port(HOST, PORT, timeout=6.0):
            stdout, stderr = server_proc.communicate(timeout=1.0)
            print("Server failed to boot!\nSTDOUT:", stdout, "\nSTDERR:", stderr)
            sys.exit(1)
        print("      Server is up and listening!")

        base_url = f"http://{HOST}:{PORT}"

        # 2. Test iPhone client connects and gets session cookie
        print("\n[2/6] iPhone PWA Client Handshake:")
        status, body, set_cookie, hdrs = make_request(f"{base_url}/d/{TOKEN}/")
        assert status == 200, f"Expected 200 from drop page, got {status}"
        assert "pd_session=" in set_cookie, "Expected pd_session cookie from drop page"
        # Extract cookie
        cookie_val = set_cookie.split(";")[0]
        print(f"      Got session cookie: {cookie_val[:25]}...")

        # Test status endpoint
        status, body, _, _ = make_request(f"{base_url}/d/{TOKEN}/status", cookie=cookie_val)
        assert status == 200, f"Status endpoint failed: {status}"
        st_data = json.loads(body.decode("utf-8"))
        assert "usable" in st_data, "Expected usable space in status"
        assert st_data["version"] == "1.7.0"
        print(f"      Status verified: {st_data['free_human']} free, {st_data['session_files']} files in session")

        # Test sync/status endpoint
        status, body, _, _ = make_request(f"{base_url}/d/{TOKEN}/sync/status", cookie=cookie_val)
        assert status == 200, f"Sync status endpoint failed: {status}"
        sync_data = json.loads(body.decode("utf-8"))
        assert "watermark" in sync_data, "Expected watermark in sync status"
        print(f"      Sync status verified: initial watermark={sync_data['watermark']}, total_synced={sync_data['total_synced']}")

        # 3. Test sequential multi-photo uploads and byte accuracy
        print("\n[3/6] iPhone Multi-Photo Upload Simulation (Byte Accuracy & Hashes):")
        test_files = [
            ("IMG_0001.JPG", os.urandom(64 * 1024)),        # 64 KB
            ("IMG_0002.HEIC", os.urandom(256 * 1024)),      # 256 KB
            ("VID_0003.MOV", os.urandom(1024 * 1024)),      # 1 MB
            ("RAW_0004.DNG", os.urandom(2 * 1024 * 1024)),  # 2 MB
        ]

        batch_id = "ac0011223344"
        for name, data in test_files:
            expected_hash = hashlib.sha256(data).hexdigest()
            url = f"{base_url}/d/{TOKEN}/upload?batch={batch_id}&name={urllib.parse.quote(name)}"
            st, res_body, _, _ = make_request(
                url,
                method="POST",
                data=data,
                headers={"Content-Type": "application/octet-stream"},
                cookie=cookie_val,
            )
            assert st == 200, f"Upload {name} failed with HTTP {st}: {res_body.decode('utf-8', errors='ignore')}"
            res_json = json.loads(res_body.decode("utf-8"))
            saved_name = res_json["files"][0]["name"]
            saved_path = DEST_DIR / saved_name
            assert saved_path.exists(), f"File {saved_name} was not saved on disk"
            actual_hash = hashlib.sha256(saved_path.read_bytes()).hexdigest()
            assert actual_hash == expected_hash, f"Hash mismatch for {name}"
            print(f"      Uploaded {name} -> saved as {saved_name} ({len(data)} B) [SHA256 Match OK]")

        # Test sync/diff endpoint
        diff_payload = json.dumps({
            "items": [
                {"name": "IMG_0001.JPG", "size": len(test_files[0][1])},
                {"name": "UNSYNCED_9999.JPG", "size": 12345}
            ]
        }).encode("utf-8")
        st, diff_body, _, _ = make_request(
            f"{base_url}/d/{TOKEN}/sync/diff",
            method="POST",
            data=diff_payload,
            headers={"Content-Type": "application/json"},
            cookie=cookie_val,
        )
        assert st == 200, f"Sync diff endpoint failed: {st}"
        diff_data = json.loads(diff_body.decode("utf-8"))
        assert "IMG_0001.JPG" in diff_data["already_synced"], f"Expected IMG_0001.JPG in already_synced: {diff_data}"
        assert "UNSYNCED_9999.JPG" in diff_data["need_upload"], f"Expected UNSYNCED_9999.JPG in need_upload: {diff_data}"
        print(f"      Sync diff verified: already_synced={diff_data['already_synced']}, need_upload={diff_data['need_upload']}")

        # 4. Test duplicate filename collisions
        print("\n[4/6] Duplicate Filename Collision Handling:")
        dup_content1 = b"First version"
        dup_content2 = b"Second version"
        for i, c in enumerate([dup_content1, dup_content2], 1):
            url = f"{base_url}/d/{TOKEN}/upload?batch={batch_id}&name=duplicate_vacation.jpg"
            st, res_body, _, _ = make_request(
                url, method="POST", data=c, headers={"Content-Type": "application/octet-stream"}, cookie=cookie_val
            )
            assert st == 200
            res_json = json.loads(res_body.decode("utf-8"))
            print(f"      Upload {i} of duplicate_vacation.jpg -> {res_json['files'][0]['name']}")

        assert (DEST_DIR / "duplicate_vacation.jpg").read_bytes() == dup_content1
        assert (DEST_DIR / "duplicate_vacation-2.jpg").read_bytes() == dup_content2
        print("      Collision deduplication verified: duplicate_vacation.jpg and duplicate_vacation-2.jpg both intact!")

        # 5. Stress test concurrent uploads (8 parallel transfers)
        print("\n[5/6] High-Concurrency Upload Stress Test (8 Simultaneous Streams):")
        concurrent_files = [(f"CONCURRENT_{i:02d}.JPG", os.urandom(128 * 1024)) for i in range(8)]

        def do_upload(item):
            fname, fbytes = item
            u = f"{base_url}/d/{TOKEN}/upload?batch={batch_id}&name={urllib.parse.quote(fname)}"
            s, b, _, _ = make_request(
                u, method="POST", data=fbytes, headers={"Content-Type": "application/octet-stream"}, cookie=cookie_val
            )
            return fname, s, b

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(do_upload, concurrent_files))
        elapsed = time.time() - start_time

        all_ok = True
        for fname, s, b in results:
            if s != 200:
                print(f"      FAILED: {fname} HTTP {s}: {b.decode('utf-8', errors='ignore')}")
                all_ok = False
            else:
                saved_name = json.loads(b.decode("utf-8"))["files"][0]["name"]
                assert (DEST_DIR / saved_name).exists(), f"File {saved_name} missing"
        if not all_ok:
            log_file = HOME_DIR / "logs" / "photo-drop.log"
            if log_file.exists():
                print("SERVER LOGS:\n" + log_file.read_text())
            assert all_ok, "Some concurrent uploads failed"
        print(f"      All 8 parallel uploads finished cleanly in {elapsed:.2f}s (zero dropped connections, zero 503 errors)")

        # 6. Test Samsung Receiver Owner Dashboard API
        print("\n[6/6] Samsung Receiver Telemetry & State API Check:")
        owner_url = f"{base_url}/owner/{OWNER_TOKEN}/api/state"
        st, o_body, _, _ = make_request(owner_url)
        assert st == 200, f"Owner state API returned {st}"
        o_data = json.loads(o_body.decode("utf-8"))
        assert "storage" in o_data, "Missing storage in owner state"
        assert "recent" in o_data, "Missing recent in owner state"
        print("      Owner state keys:", list(o_data.keys()))
        assert len(o_data["recent"]) >= 5, f"Expected at least 5 recent uploads, got {len(o_data['recent'])}"
        total_files = sum(s["files"] for s in o_data.get("sessions", []))
        assert total_files >= 14, f"Expected at least 14 total files, got {total_files}"
        print(f"      Owner Telemetry OK:")
        print(f"        Storage Free: {o_data['storage']['free_human']}")
        print(f"        Total Uploaded Files Tracked: {total_files}")
        print(f"        Total Recent Uploads Tracked: {len(o_data['recent'])}")
        print(f"        Sessions: {len(o_data.get('sessions', []))}")

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED WITH 100% SUCCESS!")
        print("=" * 60)

    finally:
        # Shutdown server
        server_proc.terminate()
        try:
            server_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            server_proc.kill()
        if TMP_DIR.exists():
            shutil.rmtree(TMP_DIR)


if __name__ == "__main__":
    main()
