"""
Advanced HTTP Sender with Connection Pooling, Async Support, and Proxy/TLS Handling
Professional-grade raw socket HTTP client
"""

import socket
import ssl
import time
import select
import threading
from typing import Optional, Dict, List, Tuple, Generator, Any
from dataclasses import dataclass, field
from enum import Enum
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
import logging
from urllib.parse import urlparse
from crlf_hunter.targets import Target, ProxyConfig, TLSConfig


class ConnectionState(Enum):
    """Connection state"""
    IDLE = "idle"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    TLS_HANDSHAKE = "tls_handshake"
    READY = "ready"
    BUSY = "busy"
    CLOSED = "closed"
    ERROR = "error"


@dataclass
class Connection:
    """Pooled connection"""
    sock: socket.socket
    ssl_sock: Optional[ssl.SSLSocket]
    target: Target
    state: ConnectionState = ConnectionState.IDLE
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    request_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    error: Optional[str] = None


@dataclass
class SendResult:
    """Result of sending a request"""
    success: bool
    response: bytes = b""
    response_time: float = 0.0
    error: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    connection_reused: bool = False
    connection_id: str = ""
    raw_request: bytes = b""
    raw_response: bytes = b""
    timing: Dict[str, float] = field(default_factory=dict)


class ConnectionPool:
    """Thread-safe connection pool for HTTP connections"""
    
    def __init__(
        self,
        max_connections: int = 10,
        max_idle_time: float = 30.0,
        max_lifetime: float = 300.0,
        max_requests_per_connection: int = 100,
    ):
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time
        self.max_lifetime = max_lifetime
        self.max_requests_per_connection = max_requests_per_connection
        
        self._pools: Dict[str, Queue] = {}  # key -> Queue of connections
        self._lock = threading.RLock()
        self._stats = {
            "created": 0,
            "reused": 0,
            "closed": 0,
            "errors": 0,
        }
    
    def _get_pool_key(self, target: Target) -> str:
        """Generate pool key for target"""
        return f"{target.scheme}://{target.netloc}"
    
    def _create_connection(self, target: Target) -> Connection:
        """Create a new connection"""
        sock = socket.create_connection(
            (target.host, target.port),
            timeout=target.tls.verify and 30 or 10  # Longer timeout for TLS
        )
        sock.settimeout(target.tls.verify and 30 or 10)
        
        # Enable TCP_NODELAY for lower latency
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        ssl_sock = None
        if target.scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = target.tls.verify
            context.verify_mode = ssl.CERT_REQUIRED if target.tls.verify else ssl.CERT_NONE
            
            if target.tls.ciphers:
                context.set_ciphers(target.tls.ciphers)
            
            if target.tls.min_version:
                version_map = {
                    "TLSv1.0": ssl.TLSVersion.TLSv1,
                    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
                    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
                }
                context.minimum_version = version_map.get(target.tls.min_version, ssl.TLSVersion.TLSv1_2)
            
            if target.tls.cert_file and target.tls.key_file:
                context.load_cert_chain(target.tls.cert_file, target.tls.key_file)
            
            if target.tls.ca_file:
                context.load_verify_locations(target.tls.ca_file)
            
            ssl_sock = context.wrap_socket(
                sock,
                server_hostname=target.tls.sni or target.host
            )
            # Perform handshake
            ssl_sock.do_handshake()
        
        conn = Connection(
            sock=sock,
            ssl_sock=ssl_sock,
            target=target,
            state=ConnectionState.READY if ssl_sock else ConnectionState.CONNECTED,
        )
        
        with self._lock:
            self._stats["created"] += 1
        
        return conn
    
    def get_connection(self, target: Target) -> Connection:
        """Get a connection from pool or create new"""
        pool_key = self._get_pool_key(target)
        
        with self._lock:
            if pool_key not in self._pools:
                self._pools[pool_key] = Queue()
            
            pool = self._pools[pool_key]
            
            # Try to get existing connection
            while not pool.empty():
                try:
                    conn = pool.get_nowait()
                    
                    # Check if connection is still valid
                    if self._is_connection_valid(conn):
                        conn.state = ConnectionState.BUSY
                        conn.last_used = time.time()
                        with self._lock:
                            self._stats["reused"] += 1
                        return conn
                    else:
                        # Connection dead, close it
                        self._close_connection(conn)
                except Empty:
                    break
            
            # Create new connection
            return self._create_connection(target)
    
    def return_connection(self, conn: Connection):
        """Return connection to pool"""
        pool_key = self._get_pool_key(conn.target)
        
        with self._lock:
            if pool_key not in self._pools:
                self._pools[pool_key] = Queue()
            
            pool = self._pools[pool_key]
            
            conn.request_count += 1
            conn.last_used = time.time()
            
            # Check if should keep
            if (conn.request_count < self.max_requests_per_connection and
                time.time() - conn.created_at < self.max_lifetime and
                conn.state != ConnectionState.ERROR):
                conn.state = ConnectionState.IDLE
                pool.put(conn)
            else:
                self._close_connection(conn)
    
    def _is_connection_valid(self, conn: Connection) -> bool:
        """Check if connection is still alive"""
        try:
            # Check socket
            if conn.ssl_sock:
                # For SSL, try to peek
                conn.ssl_sock.pending()
            else:
                # For plain socket, use select
                ready = select.select([conn.sock], [], [], 0)
                if ready[0]:
                    # Data available or connection closed
                    data = conn.sock.recv(1, socket.MSG_PEEK)
                    if not data:
                        return False
            
            # Check idle time
            if time.time() - conn.last_used > self.max_idle_time:
                return False
            
            return conn.state != ConnectionState.ERROR
        except Exception:
            return False
    
    def _close_connection(self, conn: Connection):
        """Close a connection"""
        try:
            if conn.ssl_sock:
                conn.ssl_sock.close()
            conn.sock.close()
        except Exception:
            pass
        conn.state = ConnectionState.CLOSED
        with self._lock:
            self._stats["closed"] += 1
    
    def close_all(self):
        """Close all connections in all pools"""
        with self._lock:
            for pool in self._pools.values():
                while not pool.empty():
                    try:
                        conn = pool.get_nowait()
                        self._close_connection(conn)
                    except Empty:
                        break
            self._pools.clear()
    
    def get_stats(self) -> Dict:
        """Get pool statistics"""
        with self._lock:
            active = sum(p.qsize() for p in self._pools.values())
            return {
                **self._stats,
                "active_connections": active,
                "pools": len(self._pools),
            }


class AdvancedSender:
    """Advanced HTTP sender with connection pooling and async support"""
    
    def __init__(
        self,
        default_timeout: float = 10.0,
        max_connections: int = 10,
        follow_redirects: bool = False,
        max_redirects: int = 5,
        proxy: ProxyConfig = None,
    ):
        self.default_timeout = default_timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.proxy = proxy
        
        self.pool = ConnectionPool(max_connections=max_connections)
        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock = threading.Lock()
    
    def _get_executor(self) -> ThreadPoolExecutor:
        """Get or create thread pool executor"""
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=self.pool.max_connections)
            return self._executor
    
    def send(
        self,
        target: Target,
        request: bytes,
        timeout: float = None,
    ) -> SendResult:
        """Send a single request synchronously"""
        timeout = timeout or self.default_timeout
        start_time = time.time()
        
        conn = None
        try:
            # Get connection
            conn = self.pool.get_connection(target)
            sock = conn.ssl_sock or conn.sock
            
            # Set timeout
            sock.settimeout(timeout)
            
            # Send request
            send_start = time.time()
            sock.sendall(request)
            send_time = time.time() - send_start
            
            # Receive response
            recv_start = time.time()
            response = self._receive_response(sock, timeout)
            recv_time = time.time() - recv_start
            
            total_time = time.time() - start_time
            
            # Parse basic response info
            status_code, headers = self._parse_response_headers(response)
            
            # Handle redirects
            redirect_count = 0
            final_response = response
            final_status = status_code
            final_headers = headers
            
            while (self.follow_redirects and redirect_count < self.max_redirects and
                   final_status in (301, 302, 303, 307, 308)):
                location = final_headers.get("location", "")
                if not location:
                    break
                
                # Parse redirect URL
                redirect_target = self._resolve_redirect(location, target)
                if not redirect_target:
                    break
                
                # Send redirect request
                redirect_request = self._build_redirect_request(
                    redirect_target, method="GET" if final_status in (302, 303) else "GET"
                )
                
                conn = self.pool.get_connection(redirect_target)
                sock = conn.ssl_sock or conn.sock
                sock.settimeout(timeout)
                sock.sendall(redirect_request)
                
                final_response = self._receive_response(sock, timeout)
                final_status, final_headers = self._parse_response_headers(final_response)
                redirect_count += 1
            
            conn.bytes_sent += len(request)
            conn.bytes_received += len(final_response)
            
            return SendResult(
                success=True,
                response=final_response,
                response_time=total_time,
                status_code=final_status,
                headers=final_headers,
                connection_reused=conn.request_count > 1,
                connection_id=f"{conn.target.netloc}:{id(conn)}",
                raw_request=request,
                raw_response=final_response,
                timing={
                    "total": total_time,
                    "send": send_time,
                    "receive": recv_time,
                    "connect": 0,  # Would need connection timing
                }
            )
            
        except socket.timeout:
            return SendResult(
                success=False,
                error=f"Timeout after {timeout}s",
                response_time=time.time() - start_time,
                raw_request=request,
            )
        except ConnectionRefusedError:
            return SendResult(
                success=False,
                error="Connection refused",
                response_time=time.time() - start_time,
                raw_request=request,
            )
        except ssl.SSLError as e:
            return SendResult(
                success=False,
                error=f"SSL error: {e}",
                response_time=time.time() - start_time,
                raw_request=request,
            )
        except Exception as e:
            return SendResult(
                success=False,
                error=f"{type(e).__name__}: {e}",
                response_time=time.time() - start_time,
                raw_request=request,
            )
        finally:
            if conn:
                self.pool.return_connection(conn)
    
    def _receive_response(self, sock: socket.socket, timeout: float) -> bytes:
        """Receive full HTTP response"""
        chunks = []
        total_bytes = 0
        max_size = 50 * 1024 * 1024  # 50MB limit
        
        # Set socket to non-blocking for select
        sock.setblocking(False)
        
        end_time = time.time() + timeout
        
        # First, read headers
        header_buffer = b""
        header_end = -1
        
        while header_end == -1 and time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            
            ready = select.select([sock], [], [], min(remaining, 1.0))
            if not ready[0]:
                continue
            
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                header_buffer += chunk
                header_end = header_buffer.find(b"\r\n\r\n")
                if header_end == -1:
                    header_end = header_buffer.find(b"\n\n")
            except socket.timeout:
                continue
            except BlockingIOError:
                continue
        
        if header_end == -1:
            # No header end found, return what we have
            sock.setblocking(True)
            return header_buffer
        
        # Parse headers to get Content-Length or Transfer-Encoding
        headers_part = header_buffer[:header_end + 4]
        body_start = header_end + 4
        body_buffer = header_buffer[body_start:]
        
        # Parse headers
        headers = {}
        for line in headers_part.decode("utf-8", errors="ignore").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        
        content_length = headers.get("content-length")
        transfer_encoding = headers.get("transfer-encoding", "").lower()
        is_chunked = "chunked" in transfer_encoding
        
        # Read body
        if is_chunked:
            # Read chunked encoding
            body_buffer = self._read_chunked_body(sock, body_buffer, end_time)
        elif content_length:
            # Read exact content length
            expected = int(content_length)
            while len(body_buffer) < expected and time.time() < end_time:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                ready = select.select([sock], [], [], min(remaining, 1.0))
                if not ready[0]:
                    continue
                try:
                    chunk = sock.recv(min(8192, expected - len(body_buffer)))
                    if not chunk:
                        break
                    body_buffer += chunk
                except BlockingIOError:
                    continue
        else:
            # Read until connection close
            while time.time() < end_time:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                ready = select.select([sock], [], [], min(remaining, 1.0))
                if not ready[0]:
                    continue
                try:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    body_buffer += chunk
                except BlockingIOError:
                    continue
        
        sock.setblocking(True)
        return headers_part + body_buffer
    
    def _read_chunked_body(self, sock: socket.socket, initial: bytes, end_time: float) -> bytes:
        """Read chunked transfer encoding body"""
        buffer = initial
        while time.time() < end_time:
            # Find next chunk size line
            chunk_end = buffer.find(b"\r\n")
            if chunk_end == -1:
                # Need more data
                ready = select.select([sock], [], [], 1.0)
                if ready[0]:
                    try:
                        chunk = sock.recv(8192)
                        if not chunk:
                            break
                        buffer += chunk
                    except BlockingIOError:
                        continue
                continue
            
            chunk_size_line = buffer[:chunk_end].decode("utf-8", errors="ignore").strip()
            try:
                chunk_size = int(chunk_size_line.split(";")[0], 16)
            except ValueError:
                break
            
            if chunk_size == 0:
                # Last chunk, read trailers
                buffer = buffer[chunk_end + 2:]  # Skip \r\n
                # Read trailers (simplified)
                break
            
            # Check if we have full chunk
            chunk_data_start = chunk_end + 2
            chunk_data_end = chunk_data_start + chunk_size
            
            if len(buffer) >= chunk_data_end + 2:  # +2 for trailing \r\n
                # Full chunk received
                buffer = buffer[:chunk_data_start] + buffer[chunk_data_start:chunk_data_end] + buffer[chunk_data_end + 2:]
            else:
                # Need more data
                ready = select.select([sock], [], [], 1.0)
                if ready[0]:
                    try:
                        chunk = sock.recv(8192)
                        if not chunk:
                            break
                        buffer += chunk
                    except BlockingIOError:
                        continue
        
        return buffer
    
    def _parse_response_headers(self, response: bytes) -> Tuple[int, Dict[str, str]]:
        """Parse status code and headers from response"""
        try:
            header_end = response.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = response.find(b"\n\n")
            
            if header_end == -1:
                return 0, {}
            
            headers_part = response[:header_end].decode("utf-8", errors="ignore")
            lines = headers_part.split("\r\n")
            if not lines:
                return 0, {}
            
            # Parse status line
            status_line = lines[0]
            status_code = 0
            parts = status_line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            
            return status_code, headers
        except Exception:
            return 0, {}
    
    def _resolve_redirect(self, location: str, original_target: Target) -> Optional[Target]:
        """Resolve redirect URL to target"""
        try:
            if location.startswith("http"):
                return parse_target(location)
            elif location.startswith("//"):
                return parse_target(f"{original_target.scheme}:{location}")
            elif location.startswith("/"):
                return Target(
                    original_url=f"{original_target.scheme}://{original_target.netloc}{location}",
                    scheme=original_target.scheme,
                    host=original_target.host,
                    port=original_target.port,
                    path=location,
                )
            else:
                # Relative path
                base_path = original_target.path.rsplit("/", 1)[0] + "/"
                return Target(
                    original_url=f"{original_target.scheme}://{original_target.netloc}{base_path}{location}",
                    scheme=original_target.scheme,
                    host=original_target.host,
                    port=original_target.port,
                    path=base_path + location,
                )
        except Exception:
            return None
    
    def _build_redirect_request(self, target: Target, method: str = "GET") -> bytes:
        """Build request for redirect"""
        builder = RequestBuilder(target)
        return builder.build_request(method=method)
    
    def send_batch(
        self,
        requests: List[Tuple[Target, bytes]],
        timeout: float = None,
        max_workers: int = None,
    ) -> Generator[SendResult, None, None]:
        """Send multiple requests concurrently"""
        executor = self._get_executor()
        futures = []
        
        for target, request in requests:
            future = executor.submit(self.send, target, request, timeout)
            futures.append(future)
        
        for future in as_completed(futures):
            try:
                yield future.result()
            except Exception as e:
                yield SendResult(
                    success=False,
                    error=f"Executor error: {e}",
                )
    
    def send_async(
        self,
        target: Target,
        request: bytes,
        timeout: float = None,
        callback: callable = None,
    ) -> Future:
        """Send request asynchronously"""
        executor = self._get_executor()
        future = executor.submit(self.send, target, request, timeout)
        
        if callback:
            future.add_done_callback(lambda f: callback(f.result()))
        
        return future
    
    def close(self):
        """Close all connections and executor"""
        self.pool.close_all()
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# Legacy compatibility
def send_raw_request(target: Target, request_bytes: bytes, timeout: float = 10.0) -> bytes:
    """Legacy function for backward compatibility"""
    sender = AdvancedSender(default_timeout=timeout)
    try:
        result = sender.send(target, request_bytes, timeout)
        return result.response
    finally:
        sender.close()


def send_with_delay(target: Target, request_bytes: bytes, timeout: float = 10.0, delay: float = 0.5) -> bytes:
    """Legacy function with delay"""
    result = send_raw_request(target, request_bytes, timeout)
    if delay > 0:
        time.sleep(delay)
    return result


# RequestBuilder for legacy compatibility
class RequestBuilder:
    """Simple request builder for backward compatibility"""
    
    def __init__(self, target: Target):
        self.target = target
        self.default_headers = {
            "Host": target.netloc,
            "User-Agent": "crlf-hunter/2.0",
            "Accept": "*/*",
            "Connection": "close",
        }
        self.default_headers.update(target.custom_headers)
        if target.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in target.cookies.items())
            self.default_headers["Cookie"] = cookie_str
    
    def build_request(
        self,
        method: str = "GET",
        path: str = None,
        headers: Dict[str, str] = None,
        body: bytes = None,
        query_params: Dict[str, List[str]] = None,
        http_version: str = "HTTP/1.1",
    ) -> bytes:
        if path is None:
            if query_params is not None:
                parts = []
                for k, vals in query_params.items():
                    for v in vals:
                        parts.append(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}")
                qs = "&".join(parts)
                path = self.target.path
                if qs:
                    path = f"{path}?{qs}"
            else:
                path = self.target.get_full_path()
        
        final_headers = self.default_headers.copy()
        if headers:
            final_headers.update(headers)
        
        if body and method.upper() in ["POST", "PUT", "PATCH"]:
            if "Content-Length" not in final_headers:
                final_headers["Content-Length"] = str(len(body))
            if "Content-Type" not in final_headers:
                final_headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        request_line = f"{method.upper()} {path} {http_version}"
        header_lines = [request_line]
        for k, v in final_headers.items():
            header_lines.append(f"{k}: {v}")
        
        request_str = "\r\n".join(header_lines) + "\r\n\r\n"
        request_bytes = request_str.encode("utf-8")
        
        if body:
            request_bytes += body
        
        return request_bytes
    
    def build_curl_command(
        self,
        method: str = "GET",
        path: str = None,
        headers: Dict[str, str] = None,
        body: bytes = None,
        query_params: Dict[str, List[str]] = None,
        insecure: bool = True,
    ) -> str:
        if path is None:
            if query_params is not None:
                parts = []
                for k, vals in query_params.items():
                    for v in vals:
                        parts.append(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}")
                qs = "&".join(parts)
                path = self.target.path
                if qs:
                    path = f"{path}?{qs}"
            else:
                path = self.target.get_full_path()
        
        url = f"{self.target.scheme}://{self.target.netloc}{path}"
        
        parts = ["curl"]
        parts.append(f"-X {method.upper()}")
        
        if insecure and self.target.scheme == "https":
            parts.append("-k")
        
        final_headers = self.default_headers.copy()
        if headers:
            final_headers.update(headers)
        
        for k, v in final_headers.items():
            escaped = v.replace('"', '\\"')
            parts.append(f'-H "{k}: {escaped}"')
        
        if body:
            if isinstance(body, bytes):
                body_str = body.decode("utf-8", errors="replace")
            else:
                body_str = str(body)
            escaped = body_str.replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
            parts.append(f'-d "{escaped}"')
        
        parts.append(f'"{url}"')
        
        return " ".join(parts)


# Import urllib.parse for RequestBuilder
import urllib.parse