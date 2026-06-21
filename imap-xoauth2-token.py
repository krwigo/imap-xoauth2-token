#!/usr/bin/env python3
import base64, hashlib, hmac, os, selectors, socket, ssl, threading, time, re, select
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

class Session:
    def __init__(self, sock, addr):
        self.conn_id = id(sock)
        self.addr = addr
        self.client_sock = sock
        self.upstream = None
        self.client_buf = b""
        self.upstream_buf = b""

    def run(self):
        self.client_sock.settimeout(None)
        log(f"connected conn={self.conn_id} addr={self.addr[0]}:{self.addr[1]}")
        try:
            self.write_client("* OK Gateway ready")
            self.pre_auth()
        except Exception as e:
            log(f"handler error conn={self.conn_id} err={e}", "ERROR")
        finally:
            self.close()

    def line(self, sock, buf_name, timeout=None):
        deadline = time.monotonic() + timeout if timeout else None
        buf = getattr(self, buf_name)
        while True:
            idx = buf.find(b"\r\n")
            if idx >= 0:
                line = buf[:idx].decode()
                setattr(self, buf_name, buf[idx + 2:])
                return line

            if len(buf) >= MAX_LINE_BYTES:
                raise ValueError("line too long")

            pending = sock.pending() if hasattr(sock, "pending") else 0
            if not pending:
                wait = None
                if deadline:
                    wait = deadline - time.monotonic()
                    if wait <= 0:
                        raise TimeoutError("timeout")

                r, _, _ = select.select([sock], [], [], wait)
                if not r:
                    raise TimeoutError("timeout")

            read_size = min(4096, MAX_LINE_BYTES - len(buf))
            if pending:
                read_size = min(read_size, pending)
            chunk = sock.recv(read_size)
            if not chunk:
                raise EOFError("closed")
            buf += chunk

    def client_line(self, timeout=None):
        return self.line(self.client_sock, "client_buf", timeout)

    def upstream_line(self, timeout=None):
        return self.line(self.upstream, "upstream_buf", timeout)

    def write_client(self, text):
        self.client_sock.sendall((text + "\r\n").encode())

    def write_upstream(self, text):
        self.upstream.sendall((text + "\r\n").encode())

    def pre_auth(self):
        while True:
            line = self.client_line(timeout=30)
            tag, cmd, args = parse_command(line)

            if cmd == "CAPABILITY":
                self.write_client("* CAPABILITY IMAP4rev1 AUTH=PLAIN")
                self.write_client(f"{tag} OK CAPABILITY completed")
                continue

            if cmd == "LOGIN":
                try:
                    username, password = parse_login(args)
                except Exception as e:
                    log(f"parse error conn={self.conn_id} err={e}", "ERROR")
                    self.write_client(f"{tag} NO Parse error")
                    return
                self.login(tag, username, password)
                return

            if cmd == "AUTHENTICATE":
                try:
                    username, password = self.read_plain_auth(args)
                except Exception as e:
                    log(f"parse error conn={self.conn_id} err={e}", "ERROR")
                    self.write_client(f"{tag} NO Parse error")
                    return
                self.login(tag, username, password)
                return

            log(f"unexpected pre-auth command conn={self.conn_id} cmd={cmd}", "ERROR")
            self.write_client(f"{tag} NO Please authenticate first")

    def read_plain_auth(self, args):
        parts = args.split(maxsplit=1)
        if len(parts) < 1 or parts[0].upper() != "PLAIN":
            raise ValueError("unsupported AUTHENTICATE mechanism")
        if len(parts) == 2 and parts[1].strip():
            return parse_plain_auth(parts[1])
        self.write_client("+ ")
        return parse_plain_auth(self.client_line(timeout=30).strip())

    def login(self, tag, username, password):
        if not hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), GATEWAY_PASSWORD_HASH):
            log(f"auth failed conn={self.conn_id} user={username}", "INFO")
            self.write_client(f"{tag} NO Authentication failed")
            return

        self.upstream = connect_upstream()
        if self.authenticate_upstream(tag, username):
            self.bridge()

    def authenticate_upstream(self, tag, username):
        req = google.auth.transport.requests.Request()
        delegated = SVC_ACCT.with_subject(username)
        try:
            delegated.refresh(req)
        except Exception:
            log(f"token mint failed conn={self.conn_id} mailbox={username}", "ERROR")
            self.write_client(f"{tag} NO Upstream authentication unavailable")
            return False
        access_token = delegated.token

        raw = f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode()
        xoauth2 = base64.b64encode(raw).decode()
        self.write_upstream(f"{tag} AUTHENTICATE XOAUTH2 {xoauth2}")

        while True:
            resp = self.upstream_line(timeout=30)
            s = resp.lstrip()
            if s.startswith("+"):
                self.write_upstream("")
                continue
            if s.startswith("*"):
                continue
            ok = s.upper().startswith(f"{tag.upper()} OK")
            break

        if ok:
            log(f"authenticated conn={self.conn_id} mailbox={username}")
            self.write_client(f"{tag} OK Authenticated")
        else:
            log(f"gmail auth rejected conn={self.conn_id} mailbox={username}", "INFO")
            self.write_client(f"{tag} NO Authentication failed")
        return ok

    def bridge(self):
        sel = selectors.DefaultSelector()
        sel.register(self.client_sock, selectors.EVENT_READ, self.upstream)
        sel.register(self.upstream, selectors.EVENT_READ, self.client_sock)

        if self.client_buf:
            self.upstream.sendall(self.client_buf)
            self.client_buf = b""
        if self.upstream_buf:
            self.client_sock.sendall(self.upstream_buf)
            self.upstream_buf = b""

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

    def close(self):
        try: self.client_sock.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        try: self.client_sock.close()
        except Exception: pass
        try: self.upstream.close()
        except Exception: pass

def connect_upstream():
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(30)
    s.connect((GOOGLE_IMAP_HOST, GOOGLE_IMAP_PORT))
    tls = ctx.wrap_socket(s, server_hostname=GOOGLE_IMAP_HOST)
    tls.settimeout(None)
    log(f"upstream connected host={GOOGLE_IMAP_HOST}")
    return tls

def unescape(s):
    return re.sub(r'\\(.)', r'\1', s)

def parse_command(line):
    parts = line.split(None, 2)
    tag = parts[0]
    cmd = parts[1].upper() if len(parts) > 1 else ""
    args = parts[2] if len(parts) > 2 else ""
    return tag, cmd, args

def parse_login(args):
    LOGIN_RX = re.compile(r'^("((?:\\.|[^"\\])*)"|(\S+))\s+("((?:\\.|[^"\\])*)"|(\S+))\s*$', re.I)
    m = LOGIN_RX.match(args)
    if not m:
        raise ValueError("bad LOGIN")
    user = unescape(m.group(2) if m.group(2) is not None else m.group(3))
    password = unescape(m.group(5) if m.group(5) is not None else m.group(6))
    return user, password

def parse_plain_auth(payload):
    raw = base64.b64decode(payload, validate=True).decode()
    fields = raw.split("\x00")
    if len(fields) == 2:
        user, password = fields[0], fields[1]
    elif len(fields) >= 3:
        user, password = fields[1], fields[2]
    else:
        raise ValueError("bad PLAIN payload")
    return user, password

def handle_client(sock, addr):
    Session(sock, addr).run()

def main():
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((LISTEN_HOST, LISTEN_PORT))
    listen_sock.listen(128)
    log(f"listening host={LISTEN_HOST} port={LISTEN_PORT}")

    sel = selectors.DefaultSelector()
    sel.register(listen_sock, selectors.EVENT_READ)

    try:
        while True:
            for key, _ in sel.select(timeout=None):
                sock, addr = listen_sock.accept()
                threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        log("shutting down")
    finally:
        sel.close()
        listen_sock.close()

if __name__ == "__main__":
    main()
