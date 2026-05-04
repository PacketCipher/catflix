#!/usr/bin/env python3
"""
CatFlix unified client – lightweight, stateless relay.
Offloads all connection state, TLS, and protocol handling to the VPS.
Supports HTTP/HTTPS/WebSocket (ws/wss) through the HTTP proxy,
and all TCP/UDP protocols through SOCKS5.

Environment variables:
  SCRIPT_ID, AES_KEY_B64            – mandatory
  FRONT_DOMAINS                     – comma‑separated list of Google frontable domains
  LISTEN_HOST, LISTEN_PORT, SOCKS_PORT
  MIN_BATCH_INTERVAL, MAX_BATCH_INTERVAL, MIN_BATCH_SIZE, MAX_HOLD_TIME
  PADDING_ENABLE                    – "true" to add random padding to payloads
  PADDING_MIN_EXTRA, PADDING_MAX_EXTRA – bounds for extra random bytes
"""

import asyncio, base64, datetime, json, logging, os, random, re, secrets, socket, ssl, struct, sys, tempfile, time, traceback, uuid
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ============================================================
# Configuration (environment variables override)
# ============================================================
DEPLOY_ID = os.environ.get("SCRIPT_ID", "YOUR_DEPLOY_ID")
AES_KEY_B64 = os.environ.get("AES_KEY_B64", "YOUR_BASE64_KEY")
AES_KEY = base64.b64decode(AES_KEY_B64)

# Front domain rotation
_FRONT_DOMAINS_STR = os.environ.get("FRONT_DOMAINS", "www.google.com,www.gstatic.com,ajax.googleapis.com,encrypted-tbn0.gstatic.com")
FRONT_DOMAINS = [d.strip() for d in _FRONT_DOMAINS_STR.split(",") if d.strip()]
_GOOGLE_IPS_STR = os.environ.get("GOOGLE_IPS", "216.239.38.120,216.239.38.121,216.239.38.122")
GOOGLE_IPS = [ip.strip() for ip in _GOOGLE_IPS_STR.split(",") if ip.strip()]

SCRIPT_HOST = "script.google.com"
BASE_PATH = f"/macros/s/{DEPLOY_ID}/exec"

LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", 8080))
SOCKS_PORT = int(os.environ.get("SOCKS_PORT", 1080))

# ---------- TUNING – lower these to send batches almost instantly ----------
MIN_BATCH_INTERVAL = float(os.environ.get("MIN_BATCH_INTERVAL", 0.01))   # 10 ms
MAX_BATCH_INTERVAL = float(os.environ.get("MAX_BATCH_INTERVAL", 0.1))    # 100 ms
MIN_BATCH_SIZE = int(os.environ.get("MIN_BATCH_SIZE", 0))                # 0 = send even when empty
MAX_HOLD_TIME = float(os.environ.get("MAX_HOLD_TIME", 0.1))              # force send after 0.1 s
# ---------------------------------------------------------------------------

UPLOAD_CHUNK_SIZE = 2 * 1024 * 1024
LARGE_DOWNLOAD_THRESHOLD = 40 * 1024 * 1024

# Optional payload padding (the server must also strip this padding)
PADDING_ENABLE = os.environ.get("PADDING_ENABLE", "false").lower() == "true"
PADDING_MIN_EXTRA = int(os.environ.get("PADDING_MIN_EXTRA", "0"))
PADDING_MAX_EXTRA = int(os.environ.get("PADDING_MAX_EXTRA", "512"))

# ============================================================
# Logging
# ============================================================
logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG,
    format="[CLIENT] %(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger("CatFlix")

# ============================================================
# Padding helpers (optional, client & server must agree)
# ============================================================
def pad_payload(data: bytes) -> bytes:
    """Pad data with a 4‑byte length prefix and random extra bytes."""
    extra = random.randint(PADDING_MIN_EXTRA, PADDING_MAX_EXTRA) if PADDING_ENABLE else 0
    padded = struct.pack(">I", len(data)) + data + secrets.token_bytes(extra)
    return padded

def unpad_payload(padded: bytes) -> bytes:
    """Extract original data from padded payload (length‑prefixed)."""
    if len(padded) < 4:
        raise ValueError("Padded payload too short")
    data_len = struct.unpack(">I", padded[:4])[0]
    if len(padded) < 4 + data_len:
        raise ValueError("Padded payload truncated")
    return padded[4:4 + data_len]

# ============================================================
# Google IP rotation (now per front domain)
# ============================================================
_ip_working_cache = {}   # front_domain -> last_working_ip

async def _connect_to_google(sni_host: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    global _ip_working_cache
    errors = []
    ips = list(GOOGLE_IPS)
    random.shuffle(ips)
    last_ip = _ip_working_cache.get(sni_host, GOOGLE_IPS[0])
    if last_ip in ips:
        ips.remove(last_ip)
        ips.insert(0, last_ip)
    for ip in ips:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ssl_ctx, server_hostname=sni_host),
                timeout=20
            )
            _ip_working_cache[sni_host] = ip
            log.debug("Connected to Google IP %s via SNI %s", ip, sni_host)
            return reader, writer
        except Exception as e:
            errors.append(f"{ip}: {e}")
            log.debug("IP %s failed for %s: %s", ip, sni_host, e)
    raise OSError(f"All Google IPs failed for {sni_host}: {'; '.join(errors)}")

# ============================================================
# AES helpers
# ============================================================
def aes_gcm_encrypt(plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return nonce + encryptor.update(plaintext) + encryptor.finalize() + encryptor.tag

def aes_gcm_decrypt(payload: bytes) -> bytes:
    nonce, tag = payload[:12], payload[-16:]
    ciphertext = payload[12:-16]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def unpad_data(padded: bytes) -> bytes:
    if len(padded) < 4:
        raise ValueError("Padding too short")
    data_len = struct.unpack(">I", padded[:4])[0]
    return padded[4:4+data_len]

def dechunk_body(raw: bytes) -> bytes:
    body = b""
    while raw:
        pos = raw.find(b"\r\n")
        if pos < 0: break
        try:
            size = int(raw[:pos], 16)
        except ValueError:
            break
        if size == 0: break
        data_start = pos + 2
        if len(raw) < data_start + size + 2: break
        body += raw[data_start:data_start+size]
        raw = raw[data_start+size+2:]
    return body

# ============================================================
# Domain‑fronted HTTP request (supports POST, redirects, front domain rotation)
# ============================================================
async def domain_fronted_request(host: str, path: str, query: str = "",
                                 method: str = "GET", body: bytes = None,
                                 sni_host: str = None) -> bytes:
    """Makes an HTTP request with optional SNI rotation."""
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    max_redirects = 5
    cur_host, cur_path, cur_query = host, path, query
    cur_method, cur_body = method, body
    cur_sni = sni_host or FRONT_DOMAINS[0]

    for attempt in range(max_redirects):
        log.debug("Request attempt %d: SNI=%s host=%s method=%s", attempt+1, cur_sni, cur_host, cur_method)
        reader, writer = await _connect_to_google(cur_sni)

        if cur_method == "POST" and cur_body:
            request_line = (
                f"POST {cur_path}{cur_query} HTTP/1.1\r\n"
                f"Host: {cur_host}\r\n"
                "User-Agent: CatFlix/1.0\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(cur_body)}\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request_line.encode() + cur_body)
        else:
            request_line = (
                f"GET {cur_path}{cur_query} HTTP/1.1\r\n"
                f"Host: {cur_host}\r\n"
                "User-Agent: CatFlix/1.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request_line.encode())
        await writer.drain()

        # Read response headers
        header_data = b""
        while b"\r\n\r\n" not in header_data:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=20)
            if not chunk: break
            header_data += chunk
        if b"\r\n\r\n" not in header_data:
            raise ConnectionError("Incomplete HTTP response headers")

        headers_part, body_start = header_data.split(b"\r\n\r\n", 1)
        status_line = headers_part.split(b"\r\n")[0].decode()
        status_code = int(status_line.split(" ")[1])
        log.debug("Response status: %d", status_code)

        headers = {}
        for line in headers_part.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.decode().split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if status_code in (301, 302, 303, 307, 308):
            location = headers.get("location", "")
            if not location:
                raise RuntimeError("Redirect without Location header")
            log.debug("Redirect to: %s", location[:120])
            writer.close()
            parsed = urlparse(location)
            cur_host = parsed.netloc
            cur_path = parsed.path or "/"
            cur_query = "?" + parsed.query if parsed.query else ""
            if status_code in (302, 303):
                cur_method = "GET"
                cur_body = None
            continue

        # Read body
        if "content-length" in headers:
            try:
                content_length = int(headers["content-length"])
                remaining = content_length - len(body_start)
                while remaining > 0:
                    chunk = await asyncio.wait_for(reader.read(min(65536, remaining)), timeout=20)
                    if not chunk: break
                    body_start += chunk
                    remaining -= len(chunk)
                body = body_start
            except (ValueError, asyncio.TimeoutError):
                rest = await asyncio.wait_for(reader.read(-1), timeout=30)
                body = body_start + rest
        else:
            rest = await asyncio.wait_for(reader.read(-1), timeout=30)
            body = body_start + rest

        writer.close()
        transfer_encoding = headers.get("transfer-encoding", "").lower()
        if transfer_encoding == "chunked" and "content-length" not in headers:
            body = dechunk_body(body)
        log.debug("Body received: %d bytes", len(body))
        return body

    raise RuntimeError("Too many redirects")

# ============================================================
# MITM CA Manager
# ============================================================
CA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca")
CA_KEY_FILE = os.path.join(CA_DIR, "ca.key")
CA_CERT_FILE = os.path.join(CA_DIR, "ca.crt")

class CertManager:
    def __init__(self):
        self.ca_key = None
        self.ca_cert = None
        self.cert_cache = {}
        self.cert_dir = tempfile.mkdtemp(prefix="catflix_certs_")
        self._load_or_create_ca()

    def _load_or_create_ca(self):
        if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
            with open(CA_KEY_FILE, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(CA_CERT_FILE, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            log.info("Loaded existing CA from %s", CA_DIR)
        else:
            self._create_ca()

    def _create_ca(self):
        os.makedirs(CA_DIR, exist_ok=True)
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "CatFlix CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CatFlix"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.ca_key, hashes.SHA256())
        )
        with open(CA_KEY_FILE, "wb") as f:
            f.write(self.ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        if os.name == "posix":
            os.chmod(CA_KEY_FILE, 0o600)
        with open(CA_CERT_FILE, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        log.warning("Generated new CA certificate: %s – install it in your browser's Trusted Root CAs!", CA_CERT_FILE)

    def get_cert_for_host(self, hostname: str):
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        full_pem = cert_pem + key_pem
        safe = hostname.replace("*", "_").replace(":", "_")[:120]
        cert_file = os.path.join(self.cert_dir, f"{safe}.pem")
        with open(cert_file, "wb") as f:
            f.write(full_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.load_cert_chain(cert_file, keyfile=None)
        self.cert_cache[hostname] = ctx
        log.debug("Generated TLS context for %s", hostname)
        return ctx

cert_mgr = CertManager()

# ============================================================
# Session management (SOCKS5, WebSocket, etc.)
# ============================================================
_session_queues: dict[str, asyncio.Queue] = {}
_session_poll_tasks: dict[str, asyncio.Task] = {}

def register_session(sid: str, q: asyncio.Queue):
    _session_queues[sid] = q
    log.debug("Registered session %s", sid)

def unregister_session(sid: str):
    _session_queues.pop(sid, None)
    task = _session_poll_tasks.pop(sid, None)
    if task:
        task.cancel()
    log.debug("Unregistered session %s", sid)

def cleanup_session(sid: str):
    """Stop polling and remove a dead session."""
    if sid in _session_queues:
        try:
            _session_queues[sid].put_nowait(None)   # wake writer
        except asyncio.QueueFull:
            pass
        _session_queues.pop(sid, None)
    task = _session_poll_tasks.pop(sid, None)
    if task:
        task.cancel()
    log.debug("Cleaned up stale session %s", sid)

def route_to_session(sid: str, data: bytes):
    q = _session_queues.get(sid)
    if q:
        q.put_nowait(data)
        return True
    return False

async def session_poll_task(session_id: str, req_type: str, poll_body: dict):
    while True:
        await asyncio.sleep((MIN_BATCH_INTERVAL + MAX_BATCH_INTERVAL) / 2)
        if session_id not in _session_queues:
            break
        req = {**poll_body, "session_id": session_id, "type": req_type}
        asyncio.create_task(batch_mgr.add_raw_request(req))

# ============================================================
# Stream buffer (large download reassembly)
# ============================================================
stream_buffers: dict[str, dict] = {}

# ============================================================
# Batch Manager (unified queue)
# ============================================================
class BatchManager:
    def __init__(self):
        self.queue: list[tuple[dict, asyncio.Future]] = []
        self.lock = asyncio.Lock()
        self.timer_handle = None
        self.oldest_arrival: float = 0.0

    async def _enqueue_request(self, req_obj: dict) -> asyncio.Future:
        future = asyncio.get_event_loop().create_future()
        async with self.lock:
            self.queue.append((req_obj, future))
            now = time.time()
            if len(self.queue) == 1:
                self.oldest_arrival = now
            log.debug("Queued request (queue size=%d)", len(self.queue))
            if self.timer_handle is None:
                interval = random.uniform(MIN_BATCH_INTERVAL, MAX_BATCH_INTERVAL)
                log.debug("Starting batch timer: %.2fs", interval)
                self.timer_handle = asyncio.create_task(self._fire_after_delay(interval))
        return future

    async def add_request(self, req_obj: dict) -> bytes:
        future = await self._enqueue_request(req_obj)
        return await future

    async def add_raw_request(self, req_obj: dict, route_data: bool = True) -> dict:
        req_obj["_route_data"] = route_data
        future = await self._enqueue_request(req_obj)
        return await future

    async def _fire_after_delay(self, interval: float):
        await asyncio.sleep(interval)
        async with self.lock:
            if not self.queue and MIN_BATCH_SIZE > 0:
                self.timer_handle = None
                return
            queue_size = len(self.queue)
            age = time.time() - self.oldest_arrival if self.oldest_arrival else 0
            if queue_size < MIN_BATCH_SIZE and age < MAX_HOLD_TIME and MIN_BATCH_SIZE > 0:
                new_interval = random.uniform(MIN_BATCH_INTERVAL, MAX_BATCH_INTERVAL)
                self.timer_handle = asyncio.create_task(self._fire_after_delay(new_interval))
                return
            batch = self.queue[:]
            self.queue.clear()
            self.timer_handle = None
            self.oldest_arrival = 0.0
            log.info("Sending batch of %d requests", len(batch))
        asyncio.create_task(self._process_batch(batch))

    async def _process_batch(self, batch: list[tuple[dict, asyncio.Future]]):
        if not batch:
            return
        reqs = [req for req, _ in batch]
        is_raw_list = [bool(req.get("type")) for req in reqs]
        route_data_list = [req.get("_route_data", False) for req in reqs]
        try:
            raw_data = await self._relay_batch(reqs)
        except Exception as e:
            log.error("Batch relay failed: %s", e, exc_info=True)
            for _, future in batch:
                if not future.done():
                    future.set_exception(e)
            return

        try:
            pending_futures = [f for (_, f) in batch]
            pending_is_raw = is_raw_list[:]
            pending_route_data = route_data_list[:]
            while True:
                resp_obj = json.loads(raw_data.decode())
                results = resp_obj.get("results", [])
                more = resp_obj.get("more", False)
                token = resp_obj.get("continuation_token", None)
                log.debug("Batch response: %d results, more=%s", len(results), more)

                for idx, result in enumerate(results):
                    if idx >= len(pending_futures): break
                    future = pending_futures[idx]
                    if future.done(): continue
                    is_raw = pending_is_raw[idx]
                    route_data = pending_route_data[idx]
                    self._dispatch_result(result, future, is_raw=is_raw, route_data=route_data)

                pending_futures = pending_futures[len(results):]
                pending_is_raw = pending_is_raw[len(results):]
                pending_route_data = pending_route_data[len(results):]

                if not more or not token:
                    for future in pending_futures:
                        if not future.done():
                            future.set_result(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    break

                log.info("Continuation token received; queuing meta fetch")
                meta_req = {"type": "continue", "token": token}
                raw_data = await self._relay_batch([meta_req])
                pending_is_raw = [False] * len(pending_futures)
                pending_route_data = [False] * len(pending_futures)

        except Exception as e:
            log.error("Batch processing error: %s", e, exc_info=True)

    def _dispatch_result(self, result: dict, future: asyncio.Future,
                         is_raw: bool = False, route_data: bool = False):
        # Handle session data with possible "session not found" or "closed"
        if route_data and "session_id" in result and "data" in result:
            sid = result["session_id"]
            data = base64.b64decode(result["data"]) if result["data"] else b""
            if result.get("closed"):
                cleanup_session(sid)
                future.set_result({"status": "ok"})
                return
            if "error" in result and result["error"] == "session not found":
                cleanup_session(sid)
                future.set_result({"error": "session not found"})
                return
            if route_to_session(sid, data):
                future.set_result({"status": "ok"})
            else:
                cleanup_session(sid)
                future.set_result({"error": "session not found"})
            return

        # For non‑routed raw requests, return the dict directly
        if is_raw:
            if "error" in result and result.get("error") == "session not found":
                sid = result.get("session_id")
                if sid:
                    cleanup_session(sid)
            future.set_result(result)
            return

        # HTTP response handling
        if "session_id" in result and "data" in result:
            sid = result["session_id"]
            data = base64.b64decode(result["data"]) if result["data"] else b""
            if result.get("closed"):
                cleanup_session(sid)
                future.set_result(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            if "error" in result and result["error"] == "session not found":
                cleanup_session(sid)
                future.set_result(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            if route_to_session(sid, data):
                future.set_result({})
            else:
                cleanup_session(sid)
                future.set_result({"error": "session not found"})
        elif "datagrams" in result:
            sid = result.get("session_id")
            q = _session_queues.get(sid)
            if q:
                for dg in result["datagrams"]:
                    host = dg["host"]
                    port = dg["port"]
                    data = base64.b64decode(dg["data"])
                    pkt = struct.pack("!BB", 0, 0) + b"\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port) + data
                    q.put_nowait(pkt)
                future.set_result({})
            else:
                future.set_result({"error": "session not found"})
        elif "_stream" in result:
            self._handle_stream_chunk(result, future)
        elif "status" in result:
            http = self._build_http_response(result)
            future.set_result(http)
        else:
            future.set_result(result)

    def _handle_stream_chunk(self, stream: dict, future: asyncio.Future):
        sid = stream["stream_id"]
        idx = stream["chunk_index"]
        total = stream["total_chunks"]
        body_b64 = stream["body_b64"]
        more = stream.get("more", False)
        token = stream.get("continuation_token")
        log.debug("Stream chunk: %s chunk %d/%d", sid, idx, total)

        if sid not in stream_buffers:
            stream_buffers[sid] = {
                "chunks": [None] * total,
                "total": total,
                "headers": stream.get("headers", {}),
                "future": future,
                "received": 0,
            }
        buf = stream_buffers[sid]
        buf["chunks"][idx] = base64.b64decode(body_b64)
        buf["received"] += 1

        if more and token:
            meta_req = {"type": "stream_continue", "token": token}
            asyncio.create_task(self._queue_stream_continuation(meta_req, sid))
        elif buf["received"] == total:
            full_body = b"".join(buf["chunks"])
            headers = buf["headers"]
            raw = f"HTTP/1.1 200 OK\r\n"
            skip = {"content-length", "transfer-encoding", "connection", "keep-alive", "content-encoding"}
            for k, v in headers.items():
                if k.lower() in skip: continue
                raw += f"{k}: {v}\r\n"
            raw += f"Content-Length: {len(full_body)}\r\n\r\n"
            log.info("Stream assembled: %s, size=%d", sid, len(full_body))
            future.set_result(raw.encode() + full_body)
            del stream_buffers[sid]

    async def _queue_stream_continuation(self, meta_req: dict, stream_id: str):
        try:
            raw_data = await self.add_raw_request(meta_req, route_data=False)
            resp_obj = json.loads(raw_data.decode())
            results = resp_obj.get("results", [])
            if results:
                result = results[0]
                buf = stream_buffers.get(stream_id)
                if buf:
                    self._handle_stream_chunk(result, buf["future"])
        except Exception as e:
            log.error("Stream continuation error: %s", e, exc_info=True)
            buf = stream_buffers.get(stream_id)
            if buf:
                buf["future"].set_result(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                del stream_buffers[stream_id]

    def _pick_front_domain(self) -> str:
        return random.choice(FRONT_DOMAINS)

    async def _relay_batch(self, reqs: list[dict], max_retries=10) -> bytes:
        """Relay a batch with automatic retry, front domain rotation, and optional padding."""
        sni_host = self._pick_front_domain()
        for attempt in range(max_retries):
            try:
                payload_reqs = reqs
                plain_payload = json.dumps(payload_reqs).encode()
                # Optional padding
                if PADDING_ENABLE:
                    plain_payload = pad_payload(plain_payload)
                encrypted_payload = aes_gcm_encrypt(plain_payload)
                b64_payload = base64.urlsafe_b64encode(encrypted_payload).decode()
                log.debug("Relay batch: plain=%d, encrypted=%d, b64=%d",
                          len(plain_payload), len(encrypted_payload), len(b64_payload))

                post_body = f"q={b64_payload}".encode()
                relay_body = await domain_fronted_request(
                    SCRIPT_HOST, BASE_PATH, method="POST", body=post_body, sni_host=sni_host
                )

                relay_text = relay_body.decode("ascii", errors="replace").strip()
                if not relay_text:
                    raise ValueError("Relay returned empty response")
                padding_needed = 4 - (len(relay_text) % 4)
                if padding_needed != 4:
                    relay_text += "=" * padding_needed
                padded_encrypted = base64.urlsafe_b64decode(relay_text)
                encrypted_response = unpad_data(padded_encrypted)
                plain_response = aes_gcm_decrypt(encrypted_response)
                # Unpad response if padding is enabled (server must match)
                if PADDING_ENABLE:
                    plain_response = unpad_payload(plain_response)
                log.debug("Decrypted batch response: %d bytes", len(plain_response))
                return plain_response
            except Exception as e:
                log.warning("Relay attempt %d/%d failed: %s", attempt+1, max_retries, e)
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(1)

    def _build_http_response(self, resp: dict) -> bytes:
        status = resp["status"]
        headers = resp.get("headers", {})
        body_b64 = resp.get("body", "")
        body = base64.b64decode(body_b64)
        reason = {200:"OK", 301:"Moved", 302:"Found", 404:"Not Found"}.get(status, "")
        raw = f"HTTP/1.1 {status} {reason}\r\n"
        skip = {"content-length", "transfer-encoding", "connection", "keep-alive", "content-encoding"}
        for k, v in headers.items():
            if k.lower() in skip: continue
            raw += f"{k}: {v}\r\n"
        raw += f"Content-Length: {len(body)}\r\n\r\n"
        return raw.encode() + body

batch_mgr = BatchManager()

# ============================================================
# SOCKS5 handler (TCP & UDP) – with sentinel and 64 KiB reads
# ============================================================
async def handle_socks_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        ver, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        methods = await reader.readexactly(nmethods)
        if 0x00 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(b"\x05\x00")
        await writer.drain()

        ver, cmd, rsv, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
        if cmd == 1:  # TCP CONNECT
            if atyp == 1:
                addr = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                domain_len = ord(await reader.readexactly(1))
                addr = (await reader.readexactly(domain_len)).decode()
            else:
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = struct.unpack("!H", await reader.readexactly(2))[0]
            session_id = str(uuid.uuid4())

            log.info("SOCKS5 CONNECT → %s:%d (sid=%s)", addr, port, session_id)
            connect_req = {"type": "tcp_connect", "session_id": session_id, "host": addr, "port": port}
            connect_resp = await batch_mgr.add_raw_request(connect_req, route_data=False)
            if connect_resp.get("status") != 200:
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            session_queue: asyncio.Queue = asyncio.Queue()
            register_session(session_id, session_queue)

            poll_task = asyncio.create_task(session_poll_task(session_id, "tcp_poll", {}))
            _session_poll_tasks[session_id] = poll_task

            async def reader_task():
                try:
                    while True:
                        data = await reader.read(65536)
                        if not data: break
                        req = {"type": "tcp_data", "session_id": session_id,
                               "data": base64.b64encode(data).decode()}
                        await batch_mgr.add_raw_request(req)
                except Exception as e:
                    log.debug("TCP reader ended: %s", e)
                finally:
                    session_queue.put_nowait(None)

            async def writer_task():
                try:
                    while True:
                        data = await session_queue.get()
                        if data is None: break
                        writer.write(data)
                        await writer.drain()
                except Exception as e:
                    log.debug("TCP writer ended: %s", e)

            try:
                await asyncio.gather(reader_task(), writer_task())
            finally:
                poll_task.cancel()
                unregister_session(session_id)

        elif cmd == 3:  # UDP ASSOCIATE
            session_id = str(uuid.uuid4())
            log.info("SOCKS5 UDP ASSOCIATE (sid=%s)", session_id)
            udp_req = {"type": "udp_associate", "session_id": session_id}
            udp_resp = await batch_mgr.add_raw_request(udp_req, route_data=False)
            if "port" not in udp_resp:
                writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            relay_port = udp_resp["port"]
            writer.write(struct.pack("!BBBBIH", 5, 0, 0, 1, 0, relay_port))
            await writer.drain()

            udp_queue: asyncio.Queue = asyncio.Queue()
            register_session(session_id, udp_queue)

            poll_task = asyncio.create_task(session_poll_task(session_id, "udp_poll", {}))
            _session_poll_tasks[session_id] = poll_task

            async def udp_reader():
                try:
                    while True:
                        rsv = await reader.readexactly(2)
                        frag = ord(await reader.readexactly(1))
                        atyp = ord(await reader.readexactly(1))
                        if atyp == 1:
                            dst_addr = socket.inet_ntoa(await reader.readexactly(4))
                        elif atyp == 3:
                            domain_len = ord(await reader.readexactly(1))
                            dst_addr = (await reader.readexactly(domain_len)).decode()
                        else:
                            break
                        dst_port = struct.unpack("!H", await reader.readexactly(2))[0]
                        data = await reader.read(65507)
                        if not data: break
                        req = {
                            "type": "udp_data",
                            "session_id": session_id,
                            "host": dst_addr,
                            "port": dst_port,
                            "data": base64.b64encode(data).decode()
                        }
                        await batch_mgr.add_raw_request(req)
                except Exception as e:
                    log.debug("UDP reader ended: %s", e)
                finally:
                    udp_queue.put_nowait(None)

            async def udp_writer():
                try:
                    while True:
                        pkt = await udp_queue.get()
                        if pkt is None: break
                        writer.write(pkt)
                        await writer.drain()
                except Exception as e:
                    log.debug("UDP writer ended: %s", e)

            try:
                await asyncio.gather(udp_reader(), udp_writer())
            finally:
                poll_task.cancel()
                unregister_session(session_id)
        else:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
    except Exception as e:
        log.error("SOCKS handler error: %s", e, exc_info=True)
    finally:
        writer.close()
        await writer.wait_closed()

# ============================================================
# HTTP(S) proxy handler (MITM) with full WebSocket support
# ============================================================
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        first_line = await asyncio.wait_for(reader.readline(), timeout=20)
        if not first_line: return
        parts = first_line.decode().strip().split()
        if len(parts) < 2: return
        method, url = parts[0], parts[1]
        log.debug("Client request: %s %s", method, url)

        if method == "CONNECT":
            host, port_str = url.rsplit(":", 1)
            port = int(port_str)
            await handle_connect(host, port, reader, writer)
            return

        if not url.startswith("http://") and not url.startswith("https://"):
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return

        header_block = first_line
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=20)
            if line == b"\r\n" or line == b"\n" or not line: break
            header_block += line
        headers = {}
        for line_str in header_block.decode().split("\r\n")[1:]:
            if ":" in line_str:
                k, v = line_str.split(":", 1)
                headers[k.strip()] = v.strip()

        # Force uncompressed response to avoid gzip decoding failures
        headers["Accept-Encoding"] = "identity"

        clen = int(headers.get("Content-Length", 0))
        body = b""
        if clen > 0:
            body = await asyncio.wait_for(reader.readexactly(clen), timeout=20)

        # WebSocket upgrade detection (for ws:// from browser)
        is_websocket = (
            headers.get("Upgrade", "").lower() == "websocket" and
            "Upgrade" in headers.get("Connection", "").lower()
        )
        if is_websocket:
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or 80
            session_id = str(uuid.uuid4())
            log.info("WS upgrade (plain) → %s:%d (sid=%s)", host, port, session_id)

            connect_req = {"type": "tcp_connect", "session_id": session_id, "host": host, "port": port}
            connect_resp = await batch_mgr.add_raw_request(connect_req, route_data=False)
            if connect_resp.get("status") != 200:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                return

            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            await writer.drain()

            session_queue: asyncio.Queue = asyncio.Queue()
            register_session(session_id, session_queue)

            poll_task = asyncio.create_task(session_poll_task(session_id, "tcp_poll", {}))
            _session_poll_tasks[session_id] = poll_task

            async def reader_task():
                try:
                    while True:
                        data = await reader.read(65536)
                        if not data: break
                        req = {"type": "tcp_data", "session_id": session_id,
                               "data": base64.b64encode(data).decode()}
                        await batch_mgr.add_raw_request(req)
                except Exception as e:
                    log.debug("WS raw reader ended: %s", e)
                finally:
                    session_queue.put_nowait(None)

            async def writer_task():
                try:
                    while True:
                        data = await session_queue.get()
                        if data is None: break
                        writer.write(data)
                        await writer.drain()
                except Exception as e:
                    log.debug("WS raw writer ended: %s", e)

            try:
                await asyncio.gather(reader_task(), writer_task())
            finally:
                poll_task.cancel()
                unregister_session(session_id)
            return

        # Normal HTTP request (non‑WebSocket)
        req_obj = {
            "method": method,
            "url": url,
            "headers": {k: v for k, v in headers.items() if k.lower() not in ("proxy-connection", "proxy-authorization")},
            "body": base64.b64encode(body).decode() if body else None
        }

        if body and len(body) > UPLOAD_CHUNK_SIZE:
            log.info("Large upload chunking (%d bytes)", len(body))
            future = asyncio.get_event_loop().create_future()
            await handle_large_upload(method, url, headers, body, future)
            response = await future
        elif _should_activate_large_download(method, headers, url):
            log.info("Activating large‑download streaming for %s", url)
            req_obj["_catflix_large_download"] = True
            response = await batch_mgr.add_request(req_obj)
        else:
            response = await batch_mgr.add_request(req_obj)

        writer.write(response)
        await writer.drain()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.debug("Handler error: %s", e, exc_info=True)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_connect(host: str, port: int, reader, writer):
    log.info("CONNECT → %s:%d", host, port)

    # For TLS ports, perform MITM interception.
    if port == 443:
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        ssl_ctx = cert_mgr.get_cert_for_host(host)
        loop = asyncio.get_event_loop()
        transport = writer.transport
        new_reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(new_reader)
        try:
            new_transport = await loop.start_tls(transport, protocol, ssl_ctx, server_side=True)
        except Exception as e:
            log.warning("TLS handshake failed for %s: %s", host, e)
            writer.close()
            return

        new_writer = asyncio.StreamWriter(new_transport, protocol, new_reader, loop)
        log.debug("TLS upgrade successful for %s", host)
        try:
            await _relay_http_stream(new_reader, new_writer, host)
        finally:
            try:
                new_writer.close()
            except Exception:
                pass
        return

    # For non‑TLS ports, treat as a raw TCP tunnel (plain WebSocket, plain HTTP, etc.)
    session_id = str(uuid.uuid4())
    log.info("Raw TCP tunnel → %s:%d (sid=%s)", host, port, session_id)

    connect_req = {"type": "tcp_connect", "session_id": session_id, "host": host, "port": port}
    connect_resp = await batch_mgr.add_raw_request(connect_req, route_data=False)
    if connect_resp.get("status") != 200:
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await writer.drain()
        return

    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()

    session_queue: asyncio.Queue = asyncio.Queue()
    register_session(session_id, session_queue)

    poll_task = asyncio.create_task(session_poll_task(session_id, "tcp_poll", {}))
    _session_poll_tasks[session_id] = poll_task

    async def reader_task():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                req = {"type": "tcp_data", "session_id": session_id,
                       "data": base64.b64encode(data).decode()}
                await batch_mgr.add_raw_request(req)
        except Exception as e:
            log.debug("Raw TCP reader ended: %s", e)
        finally:
            session_queue.put_nowait(None)

    async def writer_task():
        try:
            while True:
                data = await session_queue.get()
                if data is None:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            log.debug("Raw TCP writer ended: %s", e)

    try:
        await asyncio.gather(reader_task(), writer_task())
    finally:
        poll_task.cancel()
        unregister_session(session_id)

async def _relay_http_stream(reader, writer, host: str):
    while True:
        try:
            header_data = b""
            while b"\r\n\r\n" not in header_data:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=60*60)
                if not chunk: return
                header_data += chunk
            request_end = header_data.index(b"\r\n\r\n") + 4
            header_block = header_data[:request_end]
            body = header_data[request_end:]

            first_line = header_block.split(b"\r\n")[0].decode(errors="replace")
            log.debug("MITM first line (raw): %r", first_line)
            parts = first_line.split()
            if len(parts) < 2 or parts[0] not in ("GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH","CONNECT","TRACE"):
                log.error("Invalid HTTP request line: %r", first_line)
                break
            method, path = parts[0], parts[1]

            headers = {}
            for line in header_block.split(b"\r\n")[1:]:
                if b":" in line:
                    k, v = line.decode(errors="replace").split(":", 1)
                    headers[k.strip()] = v.strip()

            # Force uncompressed response
            headers["Accept-Encoding"] = "identity"

            clen = int(headers.get("Content-Length", 0))
            while len(body) < clen:
                chunk = await asyncio.wait_for(reader.read(clen - len(body)), timeout=20)
                body += chunk

            # WebSocket upgrade detection (inside MITM)
            is_websocket = (
                headers.get("Upgrade", "").lower() == "websocket" and
                "Upgrade" in headers.get("Connection", "").lower()
            )
            if is_websocket:
                log.info("WebSocket upgrade request (MITM): %s %s", method, path)
                ws_req = {
                    "type": "ws_connect",
                    "host": host,
                    "port": 443,
                    "path": path,
                    "headers": headers
                }
                result = await batch_mgr.add_raw_request(ws_req, route_data=False)
                if result.get("status") != 101:
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    await writer.drain()
                    return

                resp_line = "HTTP/1.1 101 Switching Protocols\r\n"
                resp_headers = result.get("headers", {})
                resp_str = resp_line + "\r\n".join(f"{k}: {v}" for k,v in resp_headers.items()) + "\r\n\r\n"
                writer.write(resp_str.encode())
                await writer.drain()

                session_id = result.get("session_id")
                if not session_id:
                    log.error("No session_id in WS connect result")
                    return
                await _forward_raw_websocket(session_id, reader, writer)
                continue

            # CORS preflight
            if method.upper() == "OPTIONS":
                acrm = acrh = None
                for k, v in headers.items():
                    if k.lower() == "access-control-request-method":
                        acrm = v
                    elif k.lower() == "access-control-request-headers":
                        acrh = v
                if acrm:
                    log.debug("Handling CORS preflight locally")
                    origin = headers.get("Origin", "*")
                    allow_methods = f"{acrm}, GET, POST, PUT, DELETE, PATCH, OPTIONS"
                    allow_headers = acrh or "*"
                    resp = (
                        "HTTP/1.1 204 No Content\r\n"
                        f"Access-Control-Allow-Origin: {origin}\r\n"
                        f"Access-Control-Allow-Methods: {allow_methods}\r\n"
                        f"Access-Control-Allow-Headers: {allow_headers}\r\n"
                        "Access-Control-Allow-Credentials: true\r\n"
                        "Access-Control-Max-Age: 86400\r\n"
                        "Vary: Origin\r\n"
                        "Content-Length: 0\r\n\r\n"
                    ).encode()
                    writer.write(resp)
                    await writer.drain()
                    continue

            if not path.startswith("http://") and not path.startswith("https://"):
                url = f"https://{host}{path}"
            else:
                url = path

            log.debug("MITM request: %s %s", method, url)

            req_obj = {
                "method": method,
                "url": url,
                "headers": {k: v for k, v in headers.items() if k.lower() not in ("proxy-connection", "proxy-authorization")},
                "body": base64.b64encode(body).decode() if body else None
            }

            if body and len(body) > UPLOAD_CHUNK_SIZE:
                log.info("MITM large upload: %d bytes", len(body))
                future = asyncio.get_event_loop().create_future()
                await handle_large_upload(method, url, headers, body, future)
                response = await future
            elif _should_activate_large_download(method, headers, url):
                log.info("MITM large download: %s", url)
                req_obj["_catflix_large_download"] = True
                response = await batch_mgr.add_request(req_obj)
            else:
                response = await batch_mgr.add_request(req_obj)

            writer.write(response)
            await writer.drain()
        except asyncio.IncompleteReadError:
            break
        except ConnectionError:
            break
        except Exception as e:
            log.error("MITM handler error for %s: %s", host, e, exc_info=True)
            break

async def _forward_raw_websocket(session_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    session_queue: asyncio.Queue = asyncio.Queue()
    register_session(session_id, session_queue)

    poll_task = asyncio.create_task(session_poll_task(session_id, "ws_poll", {}))
    _session_poll_tasks[session_id] = poll_task

    async def reader_task():
        try:
            while True:
                data = await reader.read(65536)
                if not data: break
                req = {"type": "ws_data", "session_id": session_id, "data": base64.b64encode(data).decode()}
                await batch_mgr.add_raw_request(req)
        except Exception as e:
            log.debug("WS raw reader ended: %s", e)
        finally:
            session_queue.put_nowait(None)

    async def writer_task():
        try:
            while True:
                data = await session_queue.get()
                if data is None: break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            log.debug("WS raw writer ended: %s", e)

    try:
        await asyncio.gather(reader_task(), writer_task())
    finally:
        poll_task.cancel()
        unregister_session(session_id)

# ============================================================
# Large upload / download helpers
# ============================================================
UPLOAD_BUFFER: dict[str, dict] = {}

async def handle_large_upload(method, url, headers, body, future):
    upload_id = str(uuid.uuid4())
    total_chunks = (len(body) + UPLOAD_CHUNK_SIZE - 1) // UPLOAD_CHUNK_SIZE
    UPLOAD_BUFFER[upload_id] = {"chunks": [None]*total_chunks, "total": total_chunks, "future": future}
    log.info("Large upload: %d bytes, split into %d chunks", len(body), total_chunks)
    for i in range(total_chunks):
        chunk = body[i*UPLOAD_CHUNK_SIZE:(i+1)*UPLOAD_CHUNK_SIZE]
        req = {
            "method": method,
            "url": url,
            "headers": headers,
            "body": base64.b64encode(chunk).decode(),
            "_catflix_upload": upload_id,
            "_catflix_chunk": i,
            "_catflix_total": total_chunks
        }
        asyncio.create_task(batch_mgr.add_request(req))
    return await future

def _is_large_download(url: str) -> bool:
    ext = url.lower().split("?")[0].split("/")[-1].split(".")[-1] if "." in url else ""
    return ext in {
        "zip","tar","gz","bz2","xz","7z","rar","exe","msi","dmg","iso","img",
        "mp4","mkv","avi","mov","webm","mp3","flac","wav","aac",
        "pdf","doc","docx","ppt","pptx","wasm"
    }

def _should_activate_large_download(method: str, headers: dict, url: str) -> bool:
    if method.upper() != "GET": return False
    range_val = None
    for k, v in headers.items():
        if k.lower() == "range":
            range_val = v
            break
    if range_val:
        m = re.match(r'bytes\s*=\s*(\d+)\s*-\s*(\d+)', range_val, re.IGNORECASE)
        if m:
            start, end = int(m.group(1)), int(m.group(2))
            if end >= start and (end - start + 1) > LARGE_DOWNLOAD_THRESHOLD:
                return True
        return False
    return _is_large_download(url)

# ============================================================
# Main
# ============================================================
async def main():
    http_server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    socks_server = await asyncio.start_server(handle_socks_client, LISTEN_HOST, SOCKS_PORT)
    log.info("CatFlix HTTP/HTTPS proxy listening on %s:%d", LISTEN_HOST, LISTEN_PORT)
    log.info("CatFlix SOCKS5 proxy listening on %s:%d", LISTEN_HOST, SOCKS_PORT)
    log.info("CA certificate: %s – install it in your browser's Trusted Root CAs.", CA_CERT_FILE)
    async with http_server, socks_server:
        await asyncio.gather(
            http_server.serve_forever(),
            socks_server.serve_forever()
        )

if __name__ == "__main__":
    asyncio.run(main())
