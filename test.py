#!/usr/bin/env python3
import imaplib, socket, os, time, sys

HOST = os.environ.get("HOST") or input("Host [localhost]: ") or "localhost"
PORT = int(os.environ.get("PORT") or input("Port [143]: ") or "143")
USER = os.environ.get("USER") or input("User [user@example.com]: ") or "user@example.com"
PASS = os.environ.get("PASS") or input("Password [password]: ") or "password"

def test_session():
    m = imaplib.IMAP4(HOST, PORT)
    tag, data = m.login(USER, PASS)
    print(f"LOGIN: {data[0].decode()}")

    tag, data = m.capability()
    caps = data[0].decode()
    print(f"CAPABILITIES: {caps}")

    tag, data = m.list()
    folders = [f.decode() for f in data]
    print(f"FOLDERS ({len(folders)}):")
    for f in folders[:50]:
        print(f"  {f}")

    tag, data = m.select("INBOX", readonly=True)
    print(f"SELECT INBOX: {data[0].decode() if isinstance(data[0], bytes) else data} messages")

    status, data = m.search(None, "ALL")
    ids = data[0].split() if data[0] else []
    print(f"SEARCH ALL: {len(ids)} messages")

    if ids:
        latest_uid = ids[-1]
        status, msg_data = m.fetch(latest_uid, "(BODY.PEEK[])")
        raw = msg_data[0][1]
        def _flatten(obj):
            if isinstance(obj, tuple):
                return b"".join(_flatten(p) for p in obj)
            if isinstance(obj, bytes):
                return obj
            return b""
        body = _flatten(raw).decode(errors="replace").strip()
        print(f"LATEST (UID {latest_uid}) body:")
        for i, line in enumerate(body.splitlines()[:30]):
            print(i, line)

    m.logout()
    print("success", flush=True)
    sys.exit(0)

if __name__ == "__main__":
    for i in range(60):
        try:
            test_session()
            break
        except ConnectionRefusedError as e:
            print(i, e, flush=True)
            time.sleep(3)
