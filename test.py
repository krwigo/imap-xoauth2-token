#!/usr/bin/env python3
import imaplib, socket

HOST = input("Host [localhost]: ") or "localhost"
PORT = int(input("Port [143]: ") or "143")
USER = input("User [user@example.com]: ") or "user@example.com"
PASS = input("Password [password]: ") or "password"

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
        status, msg_data = m.fetch(latest_uid, "(BODY.PEEK[HEADER])")
        header = msg_data[0][1].decode(errors="replace").strip()
        print(f"LATEST (UID {latest_uid}) headers:")
        for line in header.splitlines():
            print(f"  {line}")

    m.logout()

if __name__ == "__main__":
    test_session()
