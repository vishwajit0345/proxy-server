#!/usr/bin/env python3
import socket
import threading
import select
import os
import hashlib
import base64
from datetime import datetime

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8889
LOG_FILE = "proxy.log"
CACHE_DIR = "cache"
BLOCKED_FILE = "blocked.txt"
USERS_FILE = "users.txt"
AUTH_ENABLED = False
BUFFER_SIZE = 8192
MAX_CONN_QUEUE = 100

os.makedirs(CACHE_DIR, exist_ok=True)

log_lock = threading.Lock()

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} | {msg}\n"
    with log_lock:
        print(line, end="")
        try:
            with open(LOG_FILE, "a") as f:
                f.write(line)
        except Exception:
            pass

def load_blocked():
    if not os.path.exists(BLOCKED_FILE):
        return set()
    with open(BLOCKED_FILE, "r") as f:
        domains = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
    return domains

def load_users():
    users = {}
    if not os.path.exists(USERS_FILE):
        return users
    with open(USERS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                u, p = line.split(":", 1)
                users[u] = p
    return users

def hash_url(url):
    h = hashlib.sha256(url.encode()).hexdigest()
    return os.path.join(CACHE_DIR, h)

def is_blocked(host, blocked_set):
    host = (host or "").lower()
    for d in blocked_set:
        if d and d in host:
            return True
    return False

def parse_headers(header_bytes):
    headers = {}
    try:
        header_text = header_bytes.decode(errors="ignore")
        lines = header_text.split("\r\n")
        for line in lines[1:]:
            if not line:
                continue
            parts = line.split(":", 1)
            if len(parts) == 2:
                headers[parts[0].strip().lower()] = parts[1].strip()
    except:
        pass
    return headers

def require_auth(headers, users):
    auth = headers.get("proxy-authorization")
    if not auth:
        return False
    if not auth.lower().startswith("basic "):
        return False
    try:
        payload = base64.b64decode(auth.split(" ",1)[1]).decode()
        if ":" not in payload:
            return False
        u, p = payload.split(":", 1)
        return users.get(u) == p
    except:
        return False

def tunnel_data(client_sock, remote_sock):
    sockets = [client_sock, remote_sock]
    try:
        while True:
            r, _, _ = select.select(sockets, [], [], 10)
            if not r:
                continue
            for s in r:
                other = remote_sock if s is client_sock else client_sock
                data = s.recv(BUFFER_SIZE)
                if not data:
                    return
                other.sendall(data)
    except Exception:
        pass

def handle_connect(client_socket, first_line, headers, client_addr, blocked_set, users):
    try:
        target = first_line.split(" ")[1]
        if ":" in target:
            host, port_str = target.split(":", 1)
            port = int(port_str)
        else:
            host = target
            port = 443
    except Exception:
        client_socket.close()
        return

    log(f"[CONNECT] {client_addr[0]} -> {host}:{port}")

    if is_blocked(host, blocked_set):
        try:
            client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        except:
            pass
        client_socket.close()
        log(f"[BLOCKED] CONNECT to {host} blocked")
        return

    if AUTH_ENABLED and not require_auth(headers, users):
        try:
            client_socket.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
        except:
            pass
        client_socket.close()
        log(f"[AUTH FAILED] {client_addr[0]} attempted CONNECT to {host}")
        return

    try:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(10)
        remote.connect((host, port))
    except Exception as e:
        try:
            client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except:
            pass
        client_socket.close()
        log(f"[CONNECT ERROR] cannot connect to {host}:{port} -> {e}")
        return

    try:
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        tunnel_data(client_socket, remote)
    finally:
        client_socket.close()
        remote.close()
        log(f"[CONNECT CLOSED] {client_addr[0]} -> {host}:{port}")

def handle_http(client_socket, first_line, header_bytes, client_addr, blocked_set, users):
    try:
        request_line = first_line.decode(errors="ignore") if isinstance(first_line, bytes) else first_line
    except:
        request_line = ""

    parts = request_line.split(" ")
    if len(parts) < 2:
        client_socket.close()
        return

    method = parts[0]
    url = parts[1]
    headers = parse_headers(header_bytes)
    host_header = headers.get("host", "")

    host = None
    port = 80
    if ":" in host_header:
        host, port_str = host_header.split(":", 1)
        try:
            port = int(port_str)
        except:
            port = 80
    else:
        host = host_header or None

    path = url
    if url.startswith("http://") or url.startswith("https://"):
        path = "/" + "/".join(url.split("/")[3:]) if len(url.split("/")) > 3 else "/"

    log(f"[HTTP] {client_addr[0]} {method} {url}")

    if is_blocked(host or url, blocked_set):
        try:
            client_socket.sendall(
                b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 37\r\n\r\n<h1>Website Blocked by Proxy</h1>\r\n"
            )
        except:
            pass
        client_socket.close()
        log(f"[BLOCKED] {client_addr[0]} requested {url}")
        return

    if AUTH_ENABLED and not require_auth(headers, users):
        try:
            client_socket.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
        except:
            pass
        client_socket.close()
        log(f"[AUTH FAILED] {client_addr[0]} attempted {method} {url}")
        return

    cache_key = None
    cache_path = None
    is_cacheable = (method.upper() == "GET")
    if is_cacheable:
        cache_key = f"http://{host}:{port}{url}"
        cache_path = hash_url(cache_key)
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "rb") as cf:
                    cached = cf.read()
                client_socket.sendall(cached)
                log(f"[CACHE HIT] {cache_key}")
                client_socket.close()
                return
            except Exception as e:
                log(f"[CACHE READ ERROR] {e}")

    try:
        client_socket.settimeout(0.2)
        leftover = b""
        while True:
            part = client_socket.recv(BUFFER_SIZE)
            if not part:
                break
            leftover += part
    except socket.timeout:
        leftover = b""
    except:
        leftover = b""
    finally:
        client_socket.settimeout(None)

    try:
        header_text = header_bytes.decode(errors="ignore")
        header_lines = header_text.split("\r\n")
        new_first = f"{method} {path} HTTP/1.1"
        out_lines = [new_first]
        for line in header_lines[1:]:
            if not line:
                continue
            key = line.split(":",1)[0].strip().lower()
            if key in ("proxy-connection",):
                continue
            if key == "connection":
                out_lines.append("Connection: close")
            else:
                out_lines.append(line)
        out_lines.append("")
        out_req = "\r\n".join(out_lines).encode() + b"\r\n" + leftover
    except Exception as e:
        client_socket.close()
        log(f"[REQUEST BUILD ERROR] {e}")
        return

    try:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(10)
        remote.connect((host, port))
        remote.sendall(out_req)

        response_chunks = []
        while True:
            data = remote.recv(BUFFER_SIZE)
            if not data:
                break
            response_chunks.append(data)
            client_socket.sendall(data)

        full_response = b"".join(response_chunks)
        remote.close()
    except Exception as e:
        try:
            client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except:
            pass
        log(f"[REMOTE ERROR] {e}")
        client_socket.close()
        return

    if is_cacheable and cache_path:
        try:
            with open(cache_path, "wb") as cf:
                cf.write(full_response)
            log(f"[CACHE WRITE] {cache_key}")
        except Exception as e:
            log(f"[CACHE WRITE ERROR] {e}")

    client_socket.close()

def handle_client(client_socket, client_addr, blocked_set, users):
    try:
        client_socket.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client_socket.recv(BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        client_socket.settimeout(None)

        if not data:
            client_socket.close()
            return

        header_block, _, _ = data.partition(b"\r\n\r\n")
        header_lines = header_block.split(b"\r\n")
        first_line = header_lines[0]
        headers = parse_headers(header_block)

        method = first_line.decode(errors="ignore").split(" ")[0].upper()
        if method == "CONNECT":
            handle_connect(client_socket, first_line.decode(errors="ignore"), headers, client_addr, blocked_set, users)
        else:
            handle_http(client_socket, first_line, header_block, client_addr, blocked_set, users)
    except Exception as e:
        log(f"[HANDLER ERROR] {e}")
        try:
            client_socket.close()
        except:
            pass

def start_proxy():
    blocked_set = load_blocked()
    users = load_users()

    log(f"Starting proxy on {LISTEN_HOST}:{LISTEN_PORT} | Auth={'ON' if AUTH_ENABLED else 'OFF'}")
    log(f"Blocked domains: {', '.join(blocked_set) if blocked_set else '(none)'}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(MAX_CONN_QUEUE)

    try:
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr, blocked_set, users), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("Shutting down proxy.")
        server.close()

if __name__ == "__main__":
    start_proxy()
