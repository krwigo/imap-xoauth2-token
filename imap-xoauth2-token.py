#!/usr/bin/env python3
import base64, hashlib, os, selectors, socket, ssl, threading, time, re, select
import google.auth.transport.requests
from google.oauth2 import service_account

LISTEN_HOST = os.environ.get("GATEWAY_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("GATEWAY_LISTEN_PORT", "143"))
SERVICE_ACCOUNT_FILE = os.environ.get("GOOGLE_SERVICE_ACCOUNT_FILE", "service-account.json")
GOOGLE_IMAP_HOST = os.environ.get("GOOGLE_IMAP_HOST", "imap.gmail.com")
GOOGLE_IMAP_PORT = int(os.environ.get("GOOGLE_IMAP_PORT", "993"))
SESSION_IDLE_TIMEOUT = int(os.environ.get("SESSION_IDLE_TIMEOUT_SECONDS", "300"))
MAX_SESSION_SECONDS = int(os.environ.get("SESSION_MAX_SECONDS", "3600"))
MAX_LINE_BYTES = int(os.environ.get("MAX_LINE_BYTES", "8192"))
GATEWAY_PASSWORD_HASH = os.environ["GATEWAY_PASSWORD_HASH"]

SVC_ACCT = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=["https://mail.google.com/"])

def log(msg, level="INFO"):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[{ts}] {level} {msg}", flush=True)

class Reader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def read_line(self, timeout=None):
        deadline = time.monotonic() + timeout if timeout else None
        while True:
            idx = self.buf.find(b"\r\n")
            if idx >= 0:
                line = self.buf[:idx].decode()
                self.buf = self.buf[idx + 2:]
                # print("DEBUG", "READ<<", repr(line))
                return line

            if len(self.buf) >= MAX_LINE_BYTES:
                raise ValueError("line too long")

            pending = self.sock.pending() if hasattr(self.sock, "pending") else 0
            if not pending:
                wait = None
                if deadline:
                    wait = deadline - time.monotonic()
                    if wait <= 0:
                        raise TimeoutError("timeout")

                r, _, _ = select.select([self.sock], [], [], wait)
                if not r:
                    raise TimeoutError("timeout")

            read_size = min(4096, MAX_LINE_BYTES - len(self.buf))
            if pending:
                read_size = min(read_size, pending)
            chunk = self.sock.recv(read_size)
            if not chunk:
                raise EOFError("closed")
            self.buf += chunk

def wline(sock, text):
    # print("DEBUG", "WRITE>>", repr(text))
    sock.sendall((text + "\r\n").encode())

def connect_upstream():
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((GOOGLE_IMAP_HOST, GOOGLE_IMAP_PORT))
    tls = ctx.wrap_socket(s, server_hostname=GOOGLE_IMAP_HOST)
    log(f"upstream connected host={GOOGLE_IMAP_HOST}")
    return tls

def do_auth(tag, mailbox, reader, upstream_tls):
    req = google.auth.transport.requests.Request()
    # print("DEBUG", "delegating", repr(mailbox))
    delegated = SVC_ACCT.with_subject(mailbox)
    try:
        delegated.refresh(req)
    except Exception:
        log(f"token mint failed conn={id(reader)} mailbox={mailbox}", "ERROR")
        wline(reader.sock, f"{tag} NO Upstream authentication unavailable")
        return False
    access_token = delegated.token
    # print("DEBUG", "access_token", repr(access_token))

    raw = f"user={mailbox}\x01auth=Bearer {access_token}\x01\x01".encode()
    xoauth2 = base64.b64encode(raw).decode()
    wline(upstream_tls, f"{tag} AUTHENTICATE XOAUTH2 {xoauth2}")

    upstream_reader = Reader(upstream_tls)

    while True:
        resp = upstream_reader.read_line(timeout=30)
        s = resp.lstrip()
        if s.startswith("+"):
            wline(upstream_tls, "")
            continue
        if s.startswith("*"):
            continue
        ok = s.upper().startswith(f"{tag.upper()} OK")
        break

    if ok:
        log(f"authenticated conn={id(reader)} mailbox={mailbox}")
        wline(reader.sock, f"{tag} OK Authenticated")
    else:
        log(f"gmail auth rejected conn={id(reader)} mailbox={mailbox}", "INFO")
        wline(reader.sock, f"{tag} NO Authentication failed")
    return ok

def unescape(s):
    return re.sub(r'\\(.)', r'\1', s)

def parse_login(line):
    LOGIN_RX = re.compile(r'^(\S+)\s+("((?:\\.|[^"\\])*)"|(\S+))\s+("((?:\\.|[^"\\])*)"|(\S+))\s*$', re.I)
    m = LOGIN_RX.match(line)
    if not m:
        raise ValueError("bad LOGIN")
    tag = m.group(1)
    user = unescape(m.group(3) if m.group(3) is not None else m.group(4))
    password = unescape(m.group(6) if m.group(6) is not None else m.group(7))
    return tag, user, password

def parse_plain_auth(line):
    parts = line.split(maxsplit=3)
    if len(parts) < 4 or parts[1].upper() != "AUTHENTICATE" or parts[2].upper() != "PLAIN":
        raise ValueError("bad AUTHENTICATE PLAIN")
    raw = base64.b64decode(parts[3], validate=True).decode()
    fields = raw.split("\x00")
    if len(fields) == 2:
        tag, user, password = parts[0], fields[0], fields[1]
    elif len(fields) >= 3:
        tag, user, password = parts[0], fields[1], fields[2]
    else:
        raise ValueError("bad PLAIN payload")
    return tag, user, password

def parse_login_(line):
    parts = line.split(None, 2)
    tag = parts[0]
    rest = parts[2] if len(parts) > 2 else ""
    if rest.startswith('"'):
        end_q = rest.index('"', 1)
        user = rest[1:end_q]
        after = rest[end_q + 1:].strip()
        password = after.strip('"') if after else ""
    else:
        tokens = rest.split(None, 1)
        user = tokens[0] if tokens else ""
        password = tokens[1] if len(tokens) > 1 else ""
    return tag, user, password

def parse_plain_auth_(line):
    parts = line.split(maxsplit=2)
    tag = parts[0]
    raw = base64.b64decode(parts[2]).decode()
    parts_raw = raw.split("\x00")
    user = parts_raw[1] if len(parts_raw) > 1 else ""
    password = parts_raw[2] if len(parts_raw) > 2 else ""
    return tag, user, password

def read_plain_auth(reader, client_sock, auth_line):
    parts = auth_line.split(maxsplit=3)
    if len(parts) < 3 or parts[1].upper() != "AUTHENTICATE" or parts[2].upper() != "PLAIN":
        raise ValueError("unsupported AUTHENTICATE mechanism")
    if len(parts) >= 4 and parts[3].strip():
        return parse_plain_auth(auth_line)
    wline(client_sock, "+ ")
    response = reader.read_line(timeout=30).strip()
    return parse_plain_auth(f"{parts[0]} AUTHENTICATE PLAIN {response}")

def bridge(client_sock, gmail_tls):
    sel = selectors.DefaultSelector()
    sel.register(client_sock, selectors.EVENT_READ, gmail_tls)
    sel.register(gmail_tls, selectors.EVENT_READ, client_sock)

    start = time.monotonic()
    last = start

    try:
        while True:
            now = time.monotonic()
            elapsed = now - start
            if MAX_SESSION_SECONDS and elapsed >= MAX_SESSION_SECONDS:
                return

            idle = now - last
            if SESSION_IDLE_TIMEOUT and idle >= SESSION_IDLE_TIMEOUT:
                return

            waits = [60]
            if MAX_SESSION_SECONDS:
                waits.append(MAX_SESSION_SECONDS - elapsed)
            if SESSION_IDLE_TIMEOUT:
                waits.append(SESSION_IDLE_TIMEOUT - idle)

            events = sel.select(timeout=max(0, min(waits)))
            for key, _ in events:
                data = key.fileobj.recv(65536)
                if not data:
                    return
                key.data.sendall(data)
                last = time.monotonic()
    finally:
        sel.close()

def handle_client(conn, addr):
    conn_id = id(conn)
    client_sock = conn
    client_sock.settimeout(None)
    log(f"connected conn={conn_id} addr={addr[0]}:{addr[1]}")

    reader = Reader(client_sock)
    upstream_tls = None
    try:
        wline(client_sock, "* OK Gateway ready")

        while True:
            line = reader.read_line(timeout=30)
            parts = line.split(maxsplit=1)
            tag = parts[0]
            cmd_upper = parts[1].split()[0].upper() if len(parts) > 1 and parts[1].strip() else ""
            # print("LINE", repr(line), repr(cmd_upper))

            if cmd_upper == "CAPABILITY":
                wline(client_sock, "* CAPABILITY IMAP4rev1 AUTH=PLAIN")
                wline(client_sock, f"{tag} OK CAPABILITY completed")
                continue

            if cmd_upper in ("LOGIN", "AUTHENTICATE"):
                auth_line = line
                args_part = auth_line[len(tag):].lstrip()
                username = None
                password = None
                try:
                    if cmd_upper == "LOGIN":
                        _, username, password = parse_login(args_part)
                    else:
                        _, username, password = read_plain_auth(reader, client_sock, auth_line)
                except Exception as e:
                    log(f"parse error conn={conn_id} err={e}", "ERROR")
                    wline(client_sock, f"{tag} NO Parse error")
                    return

                if hashlib.sha256(password.encode()).hexdigest() != GATEWAY_PASSWORD_HASH:
                    log(f"auth failed conn={conn_id} user={username}", "INFO")
                    wline(client_sock, f"{tag} NO Authentication failed")
                    return

                upstream_tls = connect_upstream()
                if do_auth(tag, username, reader, upstream_tls):
                    bridge(reader.sock, upstream_tls)
                return

            log(f"unexpected pre-auth command conn={conn_id} cmd={cmd_upper}", "ERROR")
            wline(client_sock, f"{tag} NO Please authenticate first")

    except Exception as e:
        log(f"handler error conn={conn_id} err={e}", "ERROR")
    finally:
        try: client_sock.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        try: client_sock.close()
        except Exception: pass
        try: upstream_tls.close()
        except Exception: pass

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(128)
    log(f"listening host={LISTEN_HOST} port={LISTEN_PORT}")

    sel = selectors.DefaultSelector()
    sel.register(s, selectors.EVENT_READ)

    try:
        while True:
            for key, _ in sel.select(timeout=None):
                c, a = s.accept()
                threading.Thread(target=handle_client, args=(c, a), daemon=True).start()
    except KeyboardInterrupt:
        log("shutting down")
    finally:
        s.close()

if __name__ == "__main__":
    main()
