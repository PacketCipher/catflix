#!/usr/bin/env python3
"""
CatFlix server – production VPS backend handling HTTP, TCP, UDP, WebSocket,
with persistent sessions, session timeout cleanup, stale resource cleaners,
and full debug logging.
"""

import base64, json, logging, os, random, secrets, select, socket, struct, sys, threading, time, traceback, uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from flask import Flask, request, Response
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG,
    format="[SERVER] %(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger("CatFlix")

AES_KEY_B64 = os.environ["AES_KEY_B64"]
AES_KEY = base64.b64decode(AES_KEY_B64)
log.info("AES key loaded, first 8 bytes: %s", AES_KEY[:8].hex())

MIN_RESPONSE_SIZE = 50 * 1024
MAX_RESPONSE_SIZE = 100 * 1024
MAX_ENCRYPTED_SIZE = 40 * 1024 * 1024
DOWNLOAD_CHUNK_SIZE = 10 * 1024 * 1024
SESSION_TIMEOUT_SECONDS = int(os.environ.get("SESSION_TIMEOUT", 120))

executor = ThreadPoolExecutor(max_workers=100)

# ---- AES & padding ----
def aes_gcm_encrypt(plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    result = nonce + encryptor.update(plaintext) + encryptor.finalize() + encryptor.tag
    log.debug("AES encrypt: plain=%d → encrypted=%d", len(plaintext), len(result))
    return result

def aes_gcm_decrypt(payload: bytes) -> bytes:
    log.debug("AES decrypt: input=%d", len(payload))
    nonce, tag = payload[:12], payload[-16:]
    ciphertext = payload[12:-16]
    log.debug("  nonce=%s, tag=%s, ct_len=%d", nonce.hex(), tag.hex(), len(ciphertext))
    cipher = Cipher(algorithms.AES(AES_KEY), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    log.debug("AES decrypt: plain=%d", len(plain))
    return plain

def pad_data(data: bytes) -> bytes:
    prefixed = struct.pack(">I", len(data)) + data
    if len(prefixed) < MIN_RESPONSE_SIZE:
        target = random.randint(MIN_RESPONSE_SIZE, MAX_RESPONSE_SIZE)
        padding = secrets.token_bytes(target - len(prefixed))
        prefixed += padding
        log.debug("Padded: %d → %d", len(prefixed) - len(padding), len(prefixed))
    return prefixed

# ---- Upload reassembly & cleanup ----
upload_buffers: dict[str, dict] = {}

def handle_upload_chunk(req: dict):
    uid = req["_catflix_upload"]
    idx = req["_catflix_chunk"]
    total = req["_catflix_total"]
    body_b64 = req.get("body")
    chunk = base64.b64decode(body_b64) if body_b64 else b""
    if uid not in upload_buffers:
        upload_buffers[uid] = {"chunks": [None]*total, "total": total, "timestamp": time.time()}
    buf = upload_buffers[uid]
    buf["chunks"][idx] = chunk
    log.debug("Upload chunk %d/%d for %s", idx+1, total, uid)
    if all(c is not None for c in buf["chunks"]):
        full_body = b"".join(buf["chunks"])
        log.info("Upload reassembled: %s, size=%d", uid, len(full_body))
        del upload_buffers[uid]
        new_req = {
            "method": req["method"],
            "url": req["url"],
            "headers": req["headers"],
            "body": base64.b64encode(full_body).decode()
        }
        return proxy_single(new_req)
    return None

def cleanup_stale_uploads():
    while True:
        time.sleep(60)
        now = time.time()
        to_remove = [uid for uid, buf in list(upload_buffers.items()) if now - buf.get("timestamp",0) > 300]
        for uid in to_remove:
            del upload_buffers[uid]
            log.info("Cleaned up stale upload %s", uid)

# ---- Persistent session storage ----
tcp_sessions: dict[str, dict] = {}
udp_sessions: dict[str, dict] = {}
ws_sessions: dict[str, dict] = {}

# ---- TCP handlers ----
def handle_tcp_connect(req: dict) -> dict:
    session_id = req["session_id"]
    host = req["host"]
    port = int(req["port"])
    log.info("[TCP-CONNECT] Attempting connection to %s:%d (session %s)", host, port, session_id)
    try:
        sock = socket.create_connection((host, port), timeout=20)
        sock.settimeout(0.5)          # short timeout to loop without busy‑waiting
        log.debug("[TCP-CONNECT] Socket created, fd=%d", sock.fileno())

        tcp_sessions[session_id] = {
            'socket': sock,
            'buffer': b'',
            'lock': threading.Lock(),
            'closed': False,
            'last_access': time.time()
        }
        log.info("[TCP-CONNECT] Session %s stored in tcp_sessions (now %d active)", session_id, len(tcp_sessions))

        def reader():
            log.debug("[TCP-READER %s] Reader thread started", session_id)
            while True:
                try:
                    data = sock.recv(4096)
                    if data:
                        with tcp_sessions[session_id]['lock']:
                            tcp_sessions[session_id]['buffer'] += data
                        log.debug("[TCP-READER %s] Received %d bytes, buffer size now %d",
                                  session_id, len(data), len(tcp_sessions[session_id]['buffer']))
                    else:
                        log.info("[TCP-READER %s] recv() returned empty – remote closed gracefully", session_id)
                        break          # real EOF
                except socket.timeout:
                    # No data right now – keep waiting
                    continue
                except Exception as exc:
                    log.error("[TCP-READER %s] Exception: %s", session_id, exc)
                    break              # real error, close
            with tcp_sessions[session_id]['lock']:
                tcp_sessions[session_id]['closed'] = True
            log.info("[TCP-READER %s] Reader thread exiting, closed flag set", session_id)

        threading.Thread(target=reader, daemon=True).start()
        log.info("[TCP-CONNECT] Connection established, reader thread started for %s", session_id)
        return {"status": 200}
    except Exception as e:
        log.error("[TCP-CONNECT] %s:%d FAILED: %s", host, port, e)
        return {"status": 500, "error": str(e)}

def handle_tcp_data(req: dict) -> dict:
    session_id = req["session_id"]
    data = base64.b64decode(req.get("data", "")) if req.get("data") else b""
    log.debug("[TCP-DATA] Request for session %s, payload size=%d", session_id, len(data))
    session = tcp_sessions.get(session_id)
    if not session:
        log.warning("[TCP-DATA] Session %s NOT FOUND in tcp_sessions", session_id)
        return {"session_id": session_id, "data": "", "error": "session not found"}
    session['last_access'] = time.time()
    try:
        if data:
            log.debug("[TCP-DATA] Sending %d bytes to remote", len(data))
            session['socket'].sendall(data)
    except Exception as e:
        log.error("[TCP-DATA] sendall failed: %s", e)
        return {"session_id": session_id, "data": "", "error": str(e), "closed": True}
    with session['lock']:
        buf = session['buffer']
        session['buffer'] = b''
        closed = session['closed']
    log.debug("[TCP-DATA] Buffer drained: %d bytes, closed=%s", len(buf), closed)
    result = {"session_id": session_id, "data": base64.b64encode(buf).decode() if buf else "", "closed": closed}
    if closed:
        try: session['socket'].close()
        except: pass
        del tcp_sessions[session_id]
        log.info("[TCP-DATA] Session %s closed and removed", session_id)
    return result

def handle_tcp_poll(req: dict) -> dict:
    req["data"] = ""
    return handle_tcp_data(req)

# ---- UDP handlers (FIXED) ----
def handle_udp_associate(req: dict) -> dict:
    session_id = req["session_id"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 0))
    _, port = sock.getsockname()
    udp_sessions[session_id] = {'socket': sock, 'lock': threading.Lock(), 'last_access': time.time()}
    log.info("UDP session %s bound to port %d", session_id, port)
    return {"port": port}

def handle_udp_data(req: dict) -> dict:
    session_id = req["session_id"]
    session = udp_sessions.get(session_id)      # FIXED – fetch the dict
    if not session:
        return {"error": "session not found"}
    sock = session.get('socket')
    if not sock:
        return {"error": "session not found"}
    session['last_access'] = time.time()        # FIXED – use 'session' correctly
    data = base64.b64decode(req["data"])
    host = req["host"]
    port = int(req["port"])
    try:
        sock.sendto(data, (host, port))
    except Exception as e:
        return {"error": str(e)}
    datagrams = []
    while True:
        ready, _, _ = select.select([sock], [], [], 0)
        if not ready: break
        try:
            pkt, addr = sock.recvfrom(65507)
            datagrams.append({"host": addr[0], "port": addr[1], "data": base64.b64encode(pkt).decode()})
        except BlockingIOError:
            break
    return {"datagrams": datagrams} if datagrams else {}

def handle_udp_poll(req: dict) -> dict:
    session_id = req["session_id"]
    session = udp_sessions.get(session_id)      # FIXED
    if not session:
        return {"error": "session not found"}
    sock = session.get('socket')
    if not sock:
        return {"error": "session not found"}
    session['last_access'] = time.time()        # FIXED
    datagrams = []
    while True:
        ready, _, _ = select.select([sock], [], [], 0)
        if not ready: break
        try:
            pkt, addr = sock.recvfrom(65507)
            datagrams.append({"host": addr[0], "port": addr[1], "data": base64.b64encode(pkt).decode()})
        except BlockingIOError:
            break
    return {"datagrams": datagrams} if datagrams else {}

# ---- WebSocket handlers (requires websocket‑client) ----
try:
    from websocket import create_connection, WebSocket
    HAS_WS = True
except ImportError:
    HAS_WS = False

def handle_ws_connect(req: dict) -> dict:
    if not HAS_WS:
        return {"status": 500, "error": "WebSocket support not installed"}
    host = req["host"]
    port = req.get("port", 443)
    path = req.get("path", "/")
    ws_url = f"wss://{host}:{port}{path}" if port == 443 else f"ws://{host}:{port}{path}"
    headers = req.get("headers", {})
    session_id = req.get("session_id", str(uuid.uuid4()))

    try:
        extra_headers = {}
        for k, v in headers.items():
            if k.lower() in ("cookie", "user-agent", "origin", "sec-websocket-protocol"):
                extra_headers[k] = v
        ws = create_connection(ws_url, header=extra_headers, timeout=20)
        response_headers = dict(ws.headers) if hasattr(ws, 'headers') else {}
        response_headers.setdefault("Upgrade", "websocket")
        response_headers.setdefault("Connection", "Upgrade")

        ws_sessions[session_id] = {
            'ws': ws,
            'lock': threading.Lock(),
            'buffer': [],
            'closed': False,
            'last_access': time.time()
        }
        def reader():
            while True:
                try:
                    opcode, data = ws.recv_data()
                    if opcode is None: break
                    with ws_sessions[session_id]['lock']:
                        ws_sessions[session_id]['buffer'].append(data)
                except Exception:
                    break
            with ws_sessions[session_id]['lock']:
                ws_sessions[session_id]['closed'] = True
        threading.Thread(target=reader, daemon=True).start()

        log.info("WebSocket session %s connected to %s", session_id, ws_url)
        return {"status": 101, "headers": response_headers, "session_id": session_id}
    except Exception as e:
        log.error("WebSocket connect failed: %s", e)
        return {"status": 500, "error": str(e)}

def handle_ws_data(req: dict) -> dict:
    session_id = req["session_id"]
    data = base64.b64decode(req["data"])
    session = ws_sessions.get(session_id)
    if not session:
        return {"session_id": session_id, "data": "", "error": "session not found"}
    session['last_access'] = time.time()
    try:
        session['ws'].send(data)
    except Exception as e:
        return {"session_id": session_id, "data": "", "error": str(e), "closed": True}
    with session['lock']:
        frames = session['buffer']
        session['buffer'] = []
        closed = session['closed']
    combined = b"".join(frames)
    result = {"session_id": session_id, "data": base64.b64encode(combined).decode() if combined else "", "closed": closed}
    if closed:
        try: session['ws'].close()
        except: pass
        del ws_sessions[session_id]
        log.info("WebSocket session %s closed", session_id)
    return result

def handle_ws_poll(req: dict) -> dict:
    req["data"] = ""
    return handle_ws_data(req)

# ---- Session cleanup ----
def cleanup_stale_sessions():
    while True:
        time.sleep(60)
        now = time.time()
        timeout = SESSION_TIMEOUT_SECONDS
        for sid, s in list(tcp_sessions.items()):
            if now - s['last_access'] > timeout:
                try: s['socket'].close()
                except: pass
                del tcp_sessions[sid]
                log.info("Cleaned up stale TCP session %s", sid)
        for sid, s in list(udp_sessions.items()):
            if now - s['last_access'] > timeout:
                try: s['socket'].close()
                except: pass
                del udp_sessions[sid]
                log.info("Cleaned up stale UDP session %s", sid)
        for sid, s in list(ws_sessions.items()):
            if now - s['last_access'] > timeout:
                try: s['ws'].close()
                except: pass
                del ws_sessions[sid]
                log.info("Cleaned up stale WebSocket session %s", sid)

# ---- Cleanup for stale stream buffers and overflow chunks ----
def cleanup_stale_streams():
    while True:
        time.sleep(60)
        now = time.time()
        for sid, buf in list(stream_buffers.items()):
            if now - buf.get('timestamp', 0) > 300:
                del stream_buffers[sid]
                log.info("Cleaned up stale stream buffer %s", sid)

def cleanup_stale_overflows():
    while True:
        time.sleep(60)
        now = time.time()
        for bid, buf in list(overflow_chunks.items()):
            if now - buf.get('timestamp', 0) > 300:
                del overflow_chunks[bid]
                log.info("Cleaned up stale overflow batch %s", bid)

# ---- Single request proxy (unchanged) ----
def proxy_single(req: dict) -> dict:
    return proxy_single_with_session(req, None)

def proxy_single_with_session(req: dict, session: requests.Session | None) -> dict:
    if req.get("_catflix_large_download") and req.get("method", "GET").upper() == "GET":
        return handle_large_download(req, session)
    method = req.get("method", "GET")
    url = req.get("url", "")
    headers = req.get("headers", {})
    body_b64 = req.get("body")
    body = base64.b64decode(body_b64) if body_b64 else None
    out_headers = {k: v for k, v in headers.items()
                   if k.lower() not in ("host", "connection", "proxy-connection", "proxy-authorization", "transfer-encoding")}
    t0 = time.time()
    req_fn = session.request if session else requests.request
    try:
        resp = req_fn(method, url, headers=out_headers, data=body, timeout=20, allow_redirects=False)
        dt = time.time() - t0
        log.debug("%s %s → %d (%.2fs)", method, url[:80], resp.status_code, dt)
        return {"status": resp.status_code, "headers": dict(resp.headers), "body": base64.b64encode(resp.content).decode()}
    except Exception as e:
        dt = time.time() - t0
        log.error("%s %s error: %s (%.2fs)", method, url[:80], e, dt)
        return {"status": 502, "headers": {}, "body": base64.b64encode(f"Error: {e}".encode()).decode()}

# ---- Large download (unchanged) ----
stream_buffers: dict[str, dict] = {}

def handle_large_download(req: dict, session: requests.Session | None) -> dict:
    url = req["url"]
    headers = req.get("headers", {})
    out_headers = {k: v for k, v in headers.items()
                   if k.lower() not in ("host", "connection", "proxy-connection", "proxy-authorization", "transfer-encoding")}
    req_fn = session.request if session else requests.request
    try:
        head_resp = req_fn("HEAD", url, headers=out_headers, timeout=20)
        content_length = int(head_resp.headers.get("Content-Length", 0))
        accept_ranges = head_resp.headers.get("Accept-Ranges", "").lower()
        if content_length == 0 or accept_ranges != "bytes":
            log.warning("Large download: no range support, falling back to single fetch")
            return proxy_single_with_session(req, session)
    except Exception as e:
        log.warning("HEAD failed for %s: %s, fallback to single fetch", url, e)
        return proxy_single_with_session(req, session)

    total_size = content_length
    chunk_size = DOWNLOAD_CHUNK_SIZE
    total_chunks = (total_size + chunk_size - 1) // chunk_size
    log.info("Large download: %s, size=%d, chunks=%d", url, total_size, total_chunks)

    range_start = 0
    range_end = min(chunk_size, total_size) - 1
    range_headers = {**out_headers, "Range": f"bytes={range_start}-{range_end}"}
    try:
        resp = req_fn("GET", url, headers=range_headers, timeout=20)
        if resp.status_code not in (200, 206):
            log.warning("Range request failed, fallback to single fetch")
            return proxy_single_with_session(req, session)
        first_chunk = resp.content
        stream_id = str(uuid.uuid4())
        stream_buffers[stream_id] = {
            "url": url,
            "headers": out_headers,
            "session_cookies": session.cookies.get_dict() if session else {},
            "total_size": total_size,
            "chunk_size": chunk_size,
            "next_offset": range_end + 1,
            "timestamp": time.time()            # ← for cleanup
        }
        return {
            "_stream": {
                "stream_id": stream_id,
                "chunk_index": 0,
                "total_chunks": total_chunks,
                "headers": dict(resp.headers),
                "body_b64": base64.b64encode(first_chunk).decode(),
                "more": total_chunks > 1,
                "continuation_token": f"stream_{stream_id}_1" if total_chunks > 1 else None
            }
        }
    except Exception as e:
        log.error("Large download initial chunk error: %s", e)
        return proxy_single_with_session(req, session)

def fetch_stream_chunk(stream_id: str, chunk_index: int) -> bytes:
    buf = stream_buffers.get(stream_id)
    if not buf: raise ValueError("Unknown stream")
    url = buf["url"]
    headers = buf["headers"]
    total_size = buf["total_size"]
    chunk_size = buf["chunk_size"]
    offset = chunk_index * chunk_size
    range_start = offset
    range_end = min(offset + chunk_size, total_size) - 1
    range_headers = {**headers, "Range": f"bytes={range_start}-{range_end}"}
    cookies = buf["session_cookies"]
    resp = requests.get(url, headers=range_headers, cookies=cookies, timeout=20)
    if resp.status_code not in (200, 206):
        raise RuntimeError(f"Chunk fetch failed: {resp.status_code}")
    return base64.b64encode(resp.content).decode()

# ---- Cookie jar (unchanged) ----
def process_batch_with_cookies(reqs: list[dict]) -> list[dict]:
    if not reqs: return []
    groups = defaultdict(list)
    for idx, req in enumerate(reqs):
        if "type" in req: continue
        parsed = urlparse(req["url"])
        origin = f"{parsed.scheme}://{parsed.hostname}"
        groups[origin].append((idx, req))
    results = [None] * len(reqs)
    def process_origin(origin: str, items: list[tuple[int, dict]]):
        session = requests.Session()
        try:
            for idx, req in items:
                if "_catflix_upload" in req:
                    resp = handle_upload_chunk(req)
                    results[idx] = resp if resp is not None else {"status":200, "headers":{},"body":""}
                else:
                    results[idx] = proxy_single_with_session(req, session)
        finally:
            session.close()
    threads = []
    for origin, items in groups.items():
        t = threading.Thread(target=process_origin, args=(origin, items))
        t.start()
        threads.append(t)
    for t in threads: t.join()
    return [r for r in results if r is not None]

# ---- Multi‑split batch overflow (with timestamp for cleanup) ----
overflow_chunks: dict[str, dict] = {}

def split_results_recursive(results: list, max_encrypted: int) -> tuple[list, str | None, str]:
    batch_id = uuid.uuid4().hex
    def recursive_split(items: list) -> list[list]:
        plain = json.dumps(items).encode()
        encrypted = aes_gcm_encrypt(plain)
        if len(encrypted) <= max_encrypted: return [items]
        mid = len(items) // 2
        return recursive_split(items[:mid]) + recursive_split(items[mid:])
    chunks = recursive_split(results)
    chunk_tokens = [f"batch_{batch_id}_{idx}" for idx in range(len(chunks))]
    overflow_chunks[batch_id] = {
        "chunks": chunks,
        "tokens": chunk_tokens,
        "timestamp": time.time()          # ← for cleanup
    }
    if not chunk_tokens: return [], None, batch_id
    first_chunk = chunks[0]
    next_token = chunk_tokens[1] if len(chunk_tokens) > 1 else None
    log.info("Batch overflow split: %d results → %d chunks", len(results), len(chunks))
    return first_chunk, next_token, batch_id

def get_overflow_chunk(token: str) -> tuple[list | None, str | None]:
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != "batch": return None, None
    batch_id = parts[1]
    idx = int(parts[2])
    buf = overflow_chunks.get(batch_id)
    if not buf: return None, None
    chunks = buf["chunks"]
    if idx >= len(chunks): return None, None
    chunk = chunks[idx]
    next_token = f"batch_{batch_id}_{idx+1}" if idx+1 < len(chunks) else None
    if idx+1 == len(chunks): del overflow_chunks[batch_id]
    log.debug("Overflow chunk %d/%d", idx+1, len(chunks))
    return chunk, next_token

def get_stream_chunk(token: str) -> dict | None:
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != "stream": return None
    stream_id = parts[1]
    chunk_idx = int(parts[2])
    buf = stream_buffers.get(stream_id)
    if not buf: return None
    try:
        body_b64 = fetch_stream_chunk(stream_id, chunk_idx)
    except Exception as e:
        log.error("Stream chunk fetch error: %s", e)
        return None
    total_chunks = (buf["total_size"] + buf["chunk_size"] - 1) // buf["chunk_size"]
    more = chunk_idx + 1 < total_chunks
    next_token = f"stream_{stream_id}_{chunk_idx+1}" if more else None
    if not more: del stream_buffers[stream_id]
    return {
        "_stream": {
            "stream_id": stream_id,
            "chunk_index": chunk_idx,
            "total_chunks": total_chunks,
            "headers": {},
            "body_b64": body_b64,
            "more": more,
            "continuation_token": next_token
        }
    }

# ---- API endpoint ----
@app.route("/api", methods=["GET", "POST"])
def api():
    if request.method == "POST":
        data = request.get_json(silent=True)
        if data and "q" in data:
            q = data["q"]
        else:
            return Response("missing q", status=400)
    else:
        q = request.args.get("q", "")
    if not q:
        return Response("missing q", status=400)

    try:
        encrypted = base64.urlsafe_b64decode(q)
        decrypted = aes_gcm_decrypt(encrypted)
        payload = json.loads(decrypted)
        log.debug("Decrypted payload: %d items", len(payload))

        results = []
        normal_items = []

        for item in payload:
            if not isinstance(item, dict): continue
            t = item.get("type", "")
            log.debug("Processing item type=%s", t)
            if t == "continue":
                token = item["token"]
                chunk, next_token = get_overflow_chunk(token)
                if chunk is None: return Response("Invalid continuation token", status=404)
                response_obj = {"results": chunk, "more": next_token is not None, "continuation_token": next_token}
                response_json = json.dumps(response_obj).encode()
                encrypted_resp = aes_gcm_encrypt(response_json)
                padded = pad_data(encrypted_resp)
                return Response(padded, mimetype="application/octet-stream")
            elif t == "stream_continue":
                token = item["token"]
                stream_result = get_stream_chunk(token)
                if stream_result is None: return Response("Invalid stream token", status=404)
                resp_obj = {"results": [stream_result], "more": False}
                response_json = json.dumps(resp_obj).encode()
                encrypted_resp = aes_gcm_encrypt(response_json)
                padded = pad_data(encrypted_resp)
                return Response(padded, mimetype="application/octet-stream")
            elif t == "tcp_connect":
                results.append(handle_tcp_connect(item))
            elif t == "tcp_data":
                results.append(handle_tcp_data(item))
            elif t == "tcp_poll":
                results.append(handle_tcp_poll(item))
            elif t == "udp_associate":
                results.append(handle_udp_associate(item))
            elif t == "udp_data":
                results.append(handle_udp_data(item))
            elif t == "udp_poll":
                results.append(handle_udp_poll(item))
            elif t == "ws_connect":
                results.append(handle_ws_connect(item))
            elif t == "ws_data":
                results.append(handle_ws_data(item))
            elif t == "ws_poll":
                results.append(handle_ws_poll(item))
            elif "_catflix_upload" in item:
                resp = handle_upload_chunk(item)
                if resp is not None: results.append(resp)
            else:
                normal_items.append(item)

        if normal_items:
            normal_results = process_batch_with_cookies(normal_items)
            results.extend(normal_results)

        response_obj = {"results": results, "more": False}
        response_json = json.dumps(response_obj).encode()
        encrypted_resp = aes_gcm_encrypt(response_json)
        if len(encrypted_resp) > MAX_ENCRYPTED_SIZE:
            log.warning("Encrypted size %d exceeds limit, splitting", len(encrypted_resp))
            first_chunk, next_token, _ = split_results_recursive(results, MAX_ENCRYPTED_SIZE)
            response_obj = {
                "results": first_chunk,
                "more": next_token is not None,
                "continuation_token": next_token
            }
            response_json = json.dumps(response_obj).encode()
            encrypted_resp = aes_gcm_encrypt(response_json)

        padded = pad_data(encrypted_resp)
        log.info("Returning %d results, padded size=%d", len(results), len(padded))
        return Response(padded, mimetype="application/octet-stream")

    except Exception as e:
        log.error("API error: %s\n%s", e, traceback.format_exc())
        return Response(f"Internal error: {e}", status=500)

if __name__ == "__main__":
    threading.Thread(target=cleanup_stale_uploads, daemon=True).start()
    threading.Thread(target=cleanup_stale_sessions, daemon=True).start()
    threading.Thread(target=cleanup_stale_streams, daemon=True).start()
    threading.Thread(target=cleanup_stale_overflows, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
