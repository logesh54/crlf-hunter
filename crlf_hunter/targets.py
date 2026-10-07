"""
Advanced Target URL Parsing and Management
Supports multiple target formats, authentication, and session handling
"""

import re
import json
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from pathlib import Path
import ssl
import socket


@dataclass
class AuthConfig:
    """Authentication configuration"""
    type: str = "none"  # none, basic, bearer, cookie, header, form
    username: str = ""
    password: str = ""
    token: str = ""
    cookie_jar: Dict[str, str] = field(default_factory=dict)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    form_data: Dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    login_method: str = "POST"
    login_success_regex: str = ""
    session_cookie_name: str = "sessionid"


@dataclass
class ProxyConfig:
    """Proxy configuration"""
    enabled: bool = False
    host: str = ""
    port: int = 8080
    username: str = ""
    password: str = ""
    type: str = "http"  # http, https, socks4, socks5


@dataclass
class TLSConfig:
    """TLS/SSL configuration"""
    verify: bool = False
    cert_file: str = ""
    key_file: str = ""
    ca_file: str = ""
    ciphers: str = ""
    min_version: str = "TLSv1.2"
    max_version: str = "TLSv1.3"
    sni: str = ""
    alpn_protocols: List[str] = field(default_factory=lambda: ["http/1.1"])


@dataclass
class Target:
    """Parsed target with full configuration"""
    # Original input
    original_url: str
    raw_input: str = ""
    
    # Parsed components
    scheme: str = "http"
    host: str = ""
    port: int = 80
    path: str = "/"
    query: str = ""
    fragment: str = ""
    params: Dict[str, List[str]] = field(default_factory=dict)
    
    # Auth & session
    auth: AuthConfig = field(default_factory=AuthConfig)
    
    # Proxy
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    
    # TLS
    tls: TLSConfig = field(default_factory=TLSConfig)
    
    # Scan settings
    follow_redirects: bool = False
    max_redirects: int = 5
    custom_headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.raw_input:
            self.raw_input = self.original_url
        if not self.params and self.query:
            self.params = parse_qs(self.query, keep_blank_values=True)
        if self.port == 0:
            self.port = 443 if self.scheme == "https" else 80
    
    @property
    def netloc(self) -> str:
        """Get host:port"""
        if (self.scheme == "https" and self.port == 443) or \
           (self.scheme == "http" and self.port == 80):
            return self.host
        return f"{self.host}:{self.port}"
    
    @property
    def base_url(self) -> str:
        """Get base URL without query/fragment"""
        return f"{self.scheme}://{self.netloc}{self.path}"
    
    @property
    def full_url(self) -> str:
        """Get full URL with query"""
        url = self.base_url
        if self.query:
            url += f"?{self.query}"
        if self.fragment:
            url += f"#{self.fragment}"
        return url
    
    def get_query_params(self) -> List[str]:
        """Return list of query parameter names"""
        return list(self.params.keys())
    
    def build_query_string(self, modified_params: Dict[str, List[str]] = None) -> str:
        """Build query string from params"""
        params = modified_params or self.params
        parts = []
        for key, values in params.items():
            for v in values:
                parts.append(f"{urllib.parse.quote(key, safe='')}={urllib.parse.quote(v, safe='')}")
        return "&".join(parts)
    
    def get_full_path(self, query_string: str = None) -> str:
        """Get full path including query string"""
        qs = query_string if query_string is not None else self.query
        if qs:
            return f"{self.path}?{qs}"
        return self.path
    
    def with_modified_query(self, new_params: Dict[str, List[str]]) -> "Target":
        """Create new target with modified query params"""
        new_target = Target(
            original_url=self.original_url,
            raw_input=self.raw_input,
            scheme=self.scheme,
            host=self.host,
            port=self.port,
            path=self.path,
            query=self.build_query_string(new_params),
            fragment=self.fragment,
            params=new_params,
            auth=self.auth,
            proxy=self.proxy,
            tls=self.tls,
            follow_redirects=self.follow_redirects,
            max_redirects=self.max_redirects,
            custom_headers=self.custom_headers.copy(),
            cookies=self.cookies.copy(),
            tags=self.tags.copy(),
            metadata=self.metadata.copy(),
        )
        return new_target
    
    def with_header(self, name: str, value: str) -> "Target":
        """Create new target with additional header"""
        new_target = Target(**{k: v for k, v in asdict(self).items() if k != 'custom_headers'})
        new_target.custom_headers = self.custom_headers.copy()
        new_target.custom_headers[name] = value
        return new_target
    
    def with_cookie(self, name: str, value: str) -> "Target":
        """Create new target with additional cookie"""
        new_target = Target(**{k: v for k, v in asdict(self).items() if k != 'cookies'})
        new_target.cookies = self.cookies.copy()
        new_target.cookies[name] = value
        return new_target
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    @classmethod
    def from_dict(cls, data: Dict) -> "Target":
        """Create Target from dictionary"""
        # Handle nested objects
        auth_data = data.pop("auth", {})
        auth = AuthConfig(**auth_data) if auth_data else AuthConfig()
        
        proxy_data = data.pop("proxy", {})
        proxy = ProxyConfig(**proxy_data) if proxy_data else ProxyConfig()
        
        tls_data = data.pop("tls", {})
        tls = TLSConfig(**tls_data) if tls_data else TLSConfig()
        
        return cls(auth=auth, proxy=proxy, tls=tls, **data)
    
    @classmethod
    def from_json(cls, json_str: str) -> "Target":
        """Create Target from JSON string"""
        return cls.from_dict(json.loads(json_str))
    
    def __repr__(self):
        return f"Target({self.scheme}://{self.netloc}{self.path})"


def parse_target(url: str, **kwargs) -> Target:
    """Parse a URL string into a Target object with optional config"""
    parsed = urlparse(url)
    
    # Extract host and port
    host = parsed.hostname or ""
    port = parsed.port
    
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    
    # Parse query params
    query = parsed.query or ""
    params = parse_qs(query, keep_blank_values=True)
    
    target = Target(
        original_url=url,
        raw_input=url,
        scheme=parsed.scheme.lower() or "http",
        host=host,
        port=port,
        path=parsed.path or "/",
        query=query,
        fragment=parsed.fragment or "",
        params=params,
        **kwargs
    )
    
    return target


def parse_targets_from_file(filepath: str) -> List[Target]:
    """Parse multiple URLs from a file (one per line)"""
    targets = []
    path = Path(filepath)
    
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {filepath}")
    
    content = path.read_text(encoding="utf-8")
    
    # Try JSON first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    targets.append(parse_target(item))
                elif isinstance(item, dict):
                    targets.append(Target.from_dict(item))
        elif isinstance(data, dict):
            targets.append(Target.from_dict(data))
        return targets
    except json.JSONDecodeError:
        pass
    
    # Parse as text (one URL per line)
    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            targets.append(parse_target(line))
        except Exception as e:
            print(f"Warning: Failed to parse line {line_num}: {line} - {e}")
    
    return targets


def parse_targets_from_burp(filepath: str) -> List[Target]:
    """Parse targets from Burp Suite export (XML)"""
    # Simplified - would need full XML parsing
    targets = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(filepath)
        root = tree.getroot()
        for item in root.findall(".//item"):
            url_elem = item.find("url")
            if url_elem is not None and url_elem.text:
                targets.append(parse_target(url_elem.text))
    except Exception:
        pass
    return targets


def parse_targets_from_openapi(filepath: str) -> List[Target]:
    """Parse targets from OpenAPI/Swagger spec"""
    targets = []
    try:
        content = Path(filepath).read_text()
        spec = json.loads(content)
        servers = spec.get("servers", [{"url": ""}])
        base_url = servers[0].get("url", "")
        
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                    full_url = base_url.rstrip("/") + "/" + path.lstrip("/")
                    targets.append(parse_target(full_url))
    except Exception:
        pass
    return targets


def discover_targets_from_js(js_content: str, base_url: str) -> List[Target]:
    """Discover endpoints from JavaScript content"""
    targets = []
    # Common endpoint patterns in JS
    patterns = [
        r'["\'](/[a-zA-Z0-9_/\-\.]+\?[^"\']*)["\']',
        r'["\'](/api/[^"\']*)["\']',
        r'["\'](/v\d+/[^"\']*)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.\w+\(["\']([^"\']+)["\']',
        r'\.get\(["\']([^"\']+)["\']',
        r'\.post\(["\']([^"\']+)["\']',
    ]
    
    base = urlparse(base_url)
    base_scheme = base.scheme
    base_host = base.netloc
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content)
        for match in matches:
            if match.startswith("http"):
                url = match
            else:
                url = f"{base_scheme}://{base_host}{match}"
            try:
                targets.append(parse_target(url))
            except Exception:
                pass
    
    # Deduplicate
    seen = set()
    unique = []
    for t in targets:
        key = (t.host, t.port, t.path, t.query)
        if key not in seen:
            seen.add(key)
            unique.append(t)
    
    return unique


class TargetManager:
    """Manages multiple targets with filtering and grouping"""
    
    def __init__(self):
        self.targets: List[Target] = []
        self.groups: Dict[str, List[Target]] = {}
    
    def add(self, target: Target) -> "TargetManager":
        """Add a target"""
        self.targets.append(target)
        return self
    
    def add_from_file(self, filepath: str) -> "TargetManager":
        """Add targets from file"""
        self.targets.extend(parse_targets_from_file(filepath))
        return self
    
    def add_from_urls(self, urls: List[str]) -> "TargetManager":
        """Add targets from URL list"""
        for url in urls:
            self.targets.append(parse_target(url))
        return self
    
    def filter(self, **criteria) -> List[Target]:
        """Filter targets by criteria"""
        results = []
        for t in self.targets:
            match = True
            for key, value in criteria.items():
                if key == "scheme" and t.scheme != value:
                    match = False
                elif key == "host" and value not in t.host:
                    match = False
                elif key == "port" and t.port != value:
                    match = False
                elif key == "path_contains" and value not in t.path:
                    match = False
                elif key == "has_params" and (bool(t.params) != value):
                    match = False
                elif key == "tag" and value not in t.tags:
                    match = False
            if match:
                results.append(t)
        return results
    
    def group_by(self, key: str) -> Dict[str, List[Target]]:
        """Group targets by attribute"""
        groups = {}
        for t in self.targets:
            if key == "host":
                group_key = t.host
            elif key == "scheme":
                group_key = t.scheme
            elif key == "port":
                group_key = str(t.port)
            elif key == "domain":
                group_key = t.host.split(".")[-2] + "." + t.host.split(".")[-1] if "." in t.host else t.host
            else:
                group_key = "unknown"
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(t)
        
        self.groups = groups
        return groups
    
    def deduplicate(self) -> "TargetManager":
        """Remove duplicate targets"""
        seen = set()
        unique = []
        for t in self.targets:
            key = (t.scheme, t.host, t.port, t.path, t.query)
            if key not in seen:
                seen.add(key)
                unique.append(t)
        self.targets = unique
        return self
    
    def scope_to_domain(self, domain: str) -> "TargetManager":
        """Filter to specific domain and subdomains"""
        self.targets = [t for t in self.targets if t.host == domain or t.host.endswith(f".{domain}")]
        return self
    
    def __len__(self):
        return len(self.targets)
    
    def __iter__(self):
        return iter(self.targets)
    
    def __getitem__(self, index):
        return self.targets[index]


# Convenience functions
def load_targets(source: str, **kwargs) -> List[Target]:
    """Load targets from various sources"""
    source_path = Path(source)
    
    if source_path.exists():
        if source_path.suffix == ".json":
            with open(source_path) as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [Target.from_dict(d) if isinstance(d, dict) else parse_target(d) for d in data]
        elif source_path.suffix in [".xml", ".burp"]:
            return parse_targets_from_burp(str(source_path))
        elif source_path.suffix in [".yaml", ".yml", ".json"]:
            return parse_targets_from_openapi(str(source_path))
        else:
            return parse_targets_from_file(source)
    else:
        # Treat as single URL
        return [parse_target(source, **kwargs)]


def create_target_from_request(raw_request: str, base_url: str = None) -> Target:
    """Create target from raw HTTP request"""
    lines = raw_request.strip().split("\n")
    if not lines:
        raise ValueError("Empty request")
    
    # Parse request line
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) != 3:
        raise ValueError(f"Invalid request line: {request_line}")
    
    method, path, version = parts
    
    # Parse headers
    headers = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if not line.strip():
            body_start = i + 1
            break
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip().lower()] = val.strip()
    
    # Get host
    host = headers.get("host", "")
    if base_url:
        parsed = urlparse(base_url)
        host = parsed.netloc
        scheme = parsed.scheme
    else:
        scheme = "http"
    
    # Determine port
    if ":" in host:
        host, port_str = host.split(":", 1)
        port = int(port_str)
    else:
        port = 443 if scheme == "https" else 80
    
    # Parse query from path
    parsed_path = urlparse(path)
    query = parsed_path.query
    path_only = parsed_path.path
    
    return Target(
        original_url=f"{scheme}://{host}:{port}{path_only}?{query}" if query else f"{scheme}://{host}:{port}{path_only}",
        raw_input=raw_request,
        scheme=scheme,
        host=host,
        port=port,
        path=path_only or "/",
        query=query,
        params=parse_qs(query, keep_blank_values=True),
        custom_headers=headers,
    )