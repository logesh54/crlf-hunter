"""
Advanced HTTP Request Builder with CRLF Injection
Professional-grade raw request construction
"""

import urllib.parse
import random
import string
from typing import Dict, List, Optional, Generator, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from crlf_hunter.payloads import AdvancedPayloadGenerator, InjectionVector, get_payloads, get_marker
from crlf_hunter.targets import Target


class InjectionPointType(Enum):
    """Types of injection points"""
    QUERY_PARAM = "query_param"
    HEADER = "header"
    POST_BODY = "post_body"
    COOKIE = "cookie"
    PATH = "path"
    FRAGMENT = "fragment"
    HTTP_VERSION = "http_version"
    METHOD = "method"
    AUTH_HEADER = "auth_header"
    CUSTOM = "custom"


@dataclass
class InjectionPoint:
    """Represents a single injection point"""
    type: InjectionPointType
    name: str
    original_value: str = ""
    location: str = ""  # e.g., "query:q", "header:User-Agent"
    context: Dict = field(default_factory=dict)  # Additional context
    
    def __repr__(self):
        return f"InjectionPoint({self.location})"
    
    def __hash__(self):
        return hash((self.type, self.name, self.original_value))


@dataclass
class TestCase:
    """A single test case with injection point and payload"""
    injection_point: InjectionPoint
    payload: Dict  # Full payload info from generator
    raw_request: bytes
    curl_command: str
    target: Target  # Target this test case is for
    metadata: Dict = field(default_factory=dict)
    
    def __repr__(self):
        return f"TestCase({self.injection_point} <- {self.payload['template_name']})"


class RequestBuilder:
    """Builds raw HTTP requests with precise control"""
    
    def __init__(self, target: Target):
        self.target = target
        self.default_headers = {
            "Host": target.netloc,
            "User-Agent": "crlf-hunter/2.0 (Advanced Security Scanner)",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Cache-Control": "no-cache",
        }
        # Add custom headers from target
        self.default_headers.update(target.custom_headers)
        
        # Add cookies
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
        inject_early: bool = False,  # Inject before headers are finalized
    ) -> bytes:
        """Build complete raw HTTP request as bytes"""
        
        # Determine path
        if path is None:
            if query_params is not None:
                query_string = self._build_query_string(query_params)
                path = self.target.path
                if query_string:
                    path = f"{path}?{query_string}"
            else:
                path = self.target.get_full_path()
        
        # Merge headers
        final_headers = self.default_headers.copy()
        if headers:
            final_headers.update(headers)
        
        # Handle body
        if body is not None and method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
            if "Content-Length" not in final_headers:
                final_headers["Content-Length"] = str(len(body))
            if "Content-Type" not in final_headers:
                final_headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        # Build request line
        request_line = f"{method.upper()} {path} {http_version}"
        
        # Build header lines
        header_lines = [request_line]
        for key, value in final_headers.items():
            header_lines.append(f"{key}: {value}")
        
        # Join with CRLF
        request_str = "\r\n".join(header_lines) + "\r\n\r\n"
        request_bytes = request_str.encode("utf-8")
        
        if body:
            request_bytes += body
        
        return request_bytes
    
    def _build_query_string(self, params: Dict[str, List[str]]) -> str:
        """Build query string from params dict"""
        parts = []
        for key, values in params.items():
            for v in values:
                parts.append(f"{urllib.parse.quote(key, safe='')}={urllib.parse.quote(v, safe='')}")
        return "&".join(parts)
    
    def build_curl_command(
        self,
        method: str = "GET",
        path: str = None,
        headers: Dict[str, str] = None,
        body: bytes = None,
        query_params: Dict[str, List[str]] = None,
        insecure: bool = True,
    ) -> str:
        """Generate curl command for reproduction"""
        
        if path is None:
            if query_params is not None:
                query_string = self._build_query_string(query_params)
                path = self.target.path
                if query_string:
                    path = f"{path}?{query_string}"
            else:
                path = self.target.get_full_path()
        
        url = f"{self.target.scheme}://{self.target.netloc}{path}"
        
        parts = ["curl"]
        parts.append(f"-X {method.upper()}")
        
        if insecure and self.target.scheme == "https":
            parts.append("-k")
        
        # Headers
        final_headers = self.default_headers.copy()
        if headers:
            final_headers.update(headers)
        
        for key, value in final_headers.items():
            escaped = value.replace('"', '\\"')
            parts.append(f'-H "{key}: {escaped}"')
        
        # Body
        if body:
            if isinstance(body, bytes):
                body_str = body.decode("utf-8", errors="replace")
            else:
                body_str = str(body)
            escaped = body_str.replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
            parts.append(f'-d "{escaped}"')
        
        parts.append(f'"{url}"')
        
        return " ".join(parts)


class InjectionPointFinder:
    """Finds all possible injection points in a target"""
    
    def __init__(self, target: Target):
        self.target = target
    
    def find_all(
        self,
        header_fuzz: bool = True,
        body_fuzz: bool = True,
        path_fuzz: bool = False,
        cookie_fuzz: bool = True,
        method_fuzz: bool = False,
        custom_params: List[str] = None,
        custom_headers: List[str] = None,
    ) -> List[InjectionPoint]:
        """Find all injection points"""
        points = []
        
        # Query parameters
        for param_name, values in self.target.params.items():
            for i, val in enumerate(values):
                points.append(InjectionPoint(
                    type=InjectionPointType.QUERY_PARAM,
                    name=param_name,
                    original_value=val,
                    location=f"query:{param_name}",
                    context={"index": i, "total_values": len(values)}
                ))
        
        # Custom params (for params not in URL but to be tested)
        if custom_params:
            for param in custom_params:
                if param not in self.target.params:
                    points.append(InjectionPoint(
                        type=InjectionPointType.QUERY_PARAM,
                        name=param,
                        original_value="",
                        location=f"query:{param} (custom)",
                        context={"custom": True}
                    ))
        
        # Headers to fuzz
        if header_fuzz:
            default_headers = [
                "Referer", "User-Agent", "X-Forwarded-For", "X-Real-IP",
                "X-Originating-IP", "X-Remote-IP", "X-Client-IP",
                "Cookie", "Origin", "X-Requested-With", "X-HTTP-Method-Override",
                "Forwarded", "Client-IP", "True-Client-IP", "X-Forwarded-Host",
                "X-Forwarded-Proto", "X-Forwarded-Ssl", "X-Url-Scheme",
            ]
            
            for hdr in default_headers:
                points.append(InjectionPoint(
                    type=InjectionPointType.HEADER,
                    name=hdr,
                    original_value="",
                    location=f"header:{hdr}",
                    context={"default_fuzz": True}
                ))
        
        # Custom headers
        if custom_headers:
            for hdr in custom_headers:
                points.append(InjectionPoint(
                    type=InjectionPointType.HEADER,
                    name=hdr,
                    original_value="",
                    location=f"header:{hdr} (custom)",
                    context={"custom": True}
                ))
        
        # POST body parameters
        if body_fuzz:
            # We'd need body params from somewhere - this is a placeholder
            pass
        
        # Cookie parameters
        if cookie_fuzz and self.target.cookies:
            for cookie_name, cookie_val in self.target.cookies.items():
                points.append(InjectionPoint(
                    type=InjectionPointType.COOKIE,
                    name=cookie_name,
                    original_value=cookie_val,
                    location=f"cookie:{cookie_name}",
                    context={}
                ))
        
        # Path parameters (REST-style)
        if path_fuzz:
            path_parts = self.target.path.strip("/").split("/")
            for i, part in enumerate(path_parts):
                if part and not part.startswith(":"):
                    points.append(InjectionPoint(
                        type=InjectionPointType.PATH,
                        name=f"path_segment_{i}",
                        original_value=part,
                        location=f"path:{i}",
                        context={"segment_index": i, "total_segments": len(path_parts)}
                    ))
        
        # Fragment
        if self.target.fragment:
            points.append(InjectionPoint(
                type=InjectionPointType.FRAGMENT,
                name="fragment",
                original_value=self.target.fragment,
                location="fragment",
                context={}
            ))
        
        # HTTP Version
        if method_fuzz:
            points.append(InjectionPoint(
                type=InjectionPointType.HTTP_VERSION,
                name="http_version",
                original_value="HTTP/1.1",
                location="http_version",
                context={}
            ))
            
            # Method fuzzing
            points.append(InjectionPoint(
                type=InjectionPointType.METHOD,
                name="method",
                original_value="GET",
                location="method",
                context={}
            ))
        
        return points
    
    def find_from_spec(self, spec: Dict) -> List[InjectionPoint]:
        """Find injection points from OpenAPI spec"""
        points = []
        # This would parse OpenAPI spec for parameters
        # Simplified for now
        return points


class TestCaseGenerator:
    """Generates test cases from injection points and payloads"""
    
    def __init__(self, target: Target, mutation_level: int = 2):
        self.target = target
        self.builder = RequestBuilder(target)
        self.payload_generator = AdvancedPayloadGenerator(mutation_level=mutation_level)
        self.marker = self.payload_generator.marker
    
    def generate_for_point(
        self,
        point: InjectionPoint,
        payloads: List[Dict],
        method: str = "GET",
        body_params: Dict[str, str] = None,
    ) -> Generator[TestCase, None, None]:
        """Generate test cases for a single injection point"""
        
        for payload_info in payloads:
            payload = payload_info["payload"]
            
            # Build request based on injection point type
            if point.type == InjectionPointType.QUERY_PARAM:
                test_case = self._build_query_injection(point, payload, payload_info, method)
            elif point.type == InjectionPointType.HEADER:
                test_case = self._build_header_injection(point, payload, payload_info, method, body_params)
            elif point.type == InjectionPointType.COOKIE:
                test_case = self._build_cookie_injection(point, payload, payload_info, method)
            elif point.type == InjectionPointType.POST_BODY:
                test_case = self._build_body_injection(point, payload, payload_info, method, body_params)
            elif point.type == InjectionPointType.PATH:
                test_case = self._build_path_injection(point, payload, payload_info, method)
            elif point.type == InjectionPointType.FRAGMENT:
                test_case = self._build_fragment_injection(point, payload, payload_info, method)
            elif point.type == InjectionPointType.HTTP_VERSION:
                test_case = self._build_version_injection(point, payload, payload_info, method)
            elif point.type == InjectionPointType.METHOD:
                test_case = self._build_method_injection(point, payload, payload_info, method)
            else:
                continue
            
            if test_case:
                yield test_case
    
    def _build_query_injection(
        self, point: InjectionPoint, payload: str, payload_info: Dict, method: str
    ) -> TestCase:
        """Build query parameter injection"""
        # Create modified query params
        query_params = {k: v[:] for k, v in self.target.params.items()}
        query_params[point.name] = [payload]
        
        raw_request = self.builder.build_request(
            method=method,
            query_params=query_params,
        )
        
        curl_cmd = self.builder.build_curl_command(
            method=method,
            query_params=query_params,
        )
        
        return TestCase(
            injection_point=point,
            payload=payload_info,
            raw_request=raw_request,
            curl_command=curl_cmd,
            target=self.target,
            metadata={"injection_type": "query_param"}
        )
    
    def _build_header_injection(
        self, point: InjectionPoint, payload: str, payload_info: Dict, 
        method: str, body_params: Dict = None
    ) -> TestCase:
        """Build header injection"""
        headers = {point.name: payload}
        
        # Build body if POST
        body = None
        if method.upper() == "POST" and body_params:
            body_parts = []
            for k, v in body_params.items():
                body_parts.append(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}")
            body = "&".join(body_parts).encode("utf-8")
        
        raw_request = self.builder.build_request(
            method=method,
            headers=headers,
            body=body,
        )
        
        curl_cmd = self.builder.build_curl_command(
            method=method,
            headers=headers,
            body=body,
        )
        
        return TestCase(
            injection_point=point,
            payload=payload_info,
            raw_request=raw_request,
            curl_command=curl_cmd,
            target=self.target,
            metadata={"injection_type": "header"}
        )
    
    def _build_cookie_injection(
        self, point: InjectionPoint, payload: str, payload_info: Dict, method: str
    ) -> TestCase:
        """Build cookie injection"""
        cookies = self.target.cookies.copy()
        cookies[point.name] = payload
        
        raw_request = self.builder.build_request(
            method=method,
        )
        # Rebuild with new cookies
        builder_with_cookies = RequestBuilder(self.target.with_cookie(point.name, payload))
        raw_request = builder_with_cookies.build_request(method=method)
        
        curl_cmd = builder_with_cookies.build_curl_command(method=method)
        
        return TestCase(
            injection_point=point,
            payload=payload_info,
            raw_request=raw_request,
            curl_command=curl_cmd,
            target=self.target,
            metadata={"injection_type": "cookie"}
        )
    
    def _build_body_injection(
        self, point: InjectionPoint, payload: str, payload_info: Dict,
        method: str, body_params: Dict = None
    ) -> TestCase:
        """Build POST body injection"""
        if not body_params:
            body_params = {}
        
        modified_params = body_params.copy()
        modified_params[point.name] = payload
        
        body_parts = []
        for k, v in modified_params.items():
            body_parts.append(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}")
        body = "&".join(body_parts).encode("utf-8")
        
        raw_request = self.builder.build_request(
            method=method,
            body=body,
        )
        
        curl_cmd = self.builder.build_curl_command(
            method=method,
            body=body,
        )
        
        return TestCase(
            injection_point=point,
            payload=payload_info,
            raw_request=raw_request,
            curl_command=curl_cmd,
            target=self.target,
            metadata={"injection_type": "post_body"}
        )
    
    def _build_path_injection(
        self, point: InjectionPoint, payload: str, payload_info: Dict, method: str
    ) -> TestCase:
        """Build path injection"""
        path_parts = self.target.path.strip("/").split("/")
        segment_idx = point.context.get("segment_index", 0)
        
        if 0 <= segment_idx < len(path_parts):
            path_parts[segment_idx] = urllib.parse.quote(payload, safe="")
            new_path = "/" + "/".join(path_parts)
        else:
            new_path = self.target.path
        
        raw_request = self.builder.build_request(
            method=method,
            path=new_path,
        )
        
        curl_cmd = self.builder.build_curl_command(
            method=method,
            path=new_path,
        )
        
        return TestCase(
            injection_point=point,
            payload=payload_info,
            raw_request=raw_request,
            curl_command=curl_cmd,
            target=self.target,
            metadata={"injection_type": "path"}
        )
    
    def _build_fragment_injection(
        self, point: InjectionPoint, payload: str, payload_info: Dict, method: str
    ) -> TestCase:
        """Build fragment injection (sent in URL but not to server normally)"""
        # Note: Fragments are not sent to server, but some clients might
        path_with_fragment = f"{self.target.get_full_path()}#{urllib.parse.quote(payload, safe='')}"
        
        raw_request = self.builder.build_request(
            method=method,
            path=path_with_fragment,
        )
        
        curl_cmd = self.builder.build_curl_command(
            method=method,
            path=path_with_fragment,
        )
        
        return TestCase(
            injection_point=point,
            payload=payload_info,
            raw_request=raw_request,
            curl_command=curl_cmd,
            target=self.target,
            metadata={"injection_type": "fragment", "note": "Fragment not sent to server"}
        )
    
    def _build_version_injection(
        self, point: InjectionPoint, payload: str, payload_info: Dict, method: str
    ) -> TestCase:
        """Build HTTP version injection"""
        # Inject CRLF in HTTP version
        http_version = f"HTTP/1.1{payload}"
        
        raw_request = self.builder.build_request(
            method=method,
            http_version=http_version,
        )
        
        curl_cmd = self.builder.build_curl_command(method=method) + " --http1.1"
        
        return TestCase(
            injection_point=point,
            payload=payload_info,
            raw_request=raw_request,
            curl_command=curl_cmd,
            target=self.target,
            metadata={"injection_type": "http_version"}
        )
    
    def _build_method_injection(
        self, point: InjectionPoint, payload: str, payload_info: Dict, method: str
    ) -> TestCase:
        """Build HTTP method injection"""
        # Inject CRLF in method
        injected_method = f"GET{payload}"
        
        raw_request = self.builder.build_request(
            method=injected_method,
        )
        
        curl_cmd = self.builder.build_curl_command(method=injected_method)
        
        return TestCase(
            injection_point=point,
            payload=payload_info,
            raw_request=raw_request,
            curl_command=curl_cmd,
            target=self.target,
            metadata={"injection_type": "method"}
        )
    
    def generate_all(
        self,
        injection_points: List[InjectionPoint],
        method: str = "GET",
        body_params: Dict[str, str] = None,
        filter_severity: List[str] = None,
        filter_tags: List[str] = None,
    ) -> List[TestCase]:
        """Generate all test cases"""
        test_cases = []
        
        for point in injection_points:
            # Get payloads for this injection vector
            vector_map = {
                InjectionPointType.QUERY_PARAM: InjectionVector.QUERY_PARAM,
                InjectionPointType.HEADER: InjectionVector.HEADER,
                InjectionPointType.POST_BODY: InjectionVector.POST_BODY,
                InjectionPointType.COOKIE: InjectionVector.COOKIE,
                InjectionPointType.PATH: InjectionVector.QUERY_PARAM,  # Similar to query
            }
            
            vector = vector_map.get(point.type, InjectionVector.QUERY_PARAM)
            payloads = self.payload_generator.generate_for_vector(vector)
            
            # Filter by severity
            if filter_severity:
                payloads = [p for p in payloads if p["severity"] in filter_severity]
            
            # Filter by tags
            if filter_tags:
                payloads = [p for p in payloads if any(t in p["tags"] for t in filter_tags)]
            
            for test_case in self.generate_for_point(point, payloads, method, body_params):
                test_cases.append(test_case)
        
        return test_cases


# Legacy compatibility functions
def find_injection_points(target: Target, header_fuzz: bool = False, body_fuzz: bool = False, 
                          method: str = "GET", body_params: Dict = None) -> List[InjectionPoint]:
    """Legacy function for backward compatibility"""
    finder = InjectionPointFinder(target)
    return finder.find_all(header_fuzz=header_fuzz, body_fuzz=body_fuzz)


def build_raw_request(target: Target, injection_point: InjectionPoint, payload: str,
                      method: str = "GET", headers: Dict = None, 
                      body_params: Dict = None, host_header: str = None) -> bytes:
    """Legacy function for backward compatibility"""
    builder = RequestBuilder(target)
    
    # Convert legacy InjectionPoint to new format
    if injection_point.type == "query":
        query_params = {k: v[:] for k, v in target.params.items()}
        query_params[injection_point.name] = [payload]
        return builder.build_request(method=method, query_params=query_params)
    elif injection_point.type == "header":
        h = headers or {}
        h[injection_point.name] = payload
        body = None
        if method.upper() == "POST" and body_params:
            body_parts = []
            for k, v in body_params.items():
                body_parts.append(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}")
            body = "&".join(body_parts).encode("utf-8")
        return builder.build_request(method=method, headers=h, body=body)
    elif injection_point.type == "body":
        if not body_params:
            body_params = {}
        modified = body_params.copy()
        modified[injection_point.name] = [payload]
        body_parts = []
        for k, v in modified.items():
            body_parts.append(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}")
        body = "&".join(body_parts).encode("utf-8")
        return builder.build_request(method=method, body=body)
    
    return builder.build_request(method=method)


def generate_test_cases(target: Target, header_fuzz: bool = False, body_fuzz: bool = False,
                        method: str = "GET", body_params: Dict = None) -> List[Dict]:
    """Legacy function for backward compatibility"""
    finder = InjectionPointFinder(target)
    points = finder.find_all(header_fuzz=header_fuzz, body_fuzz=body_fuzz)
    
    generator = TestCaseGenerator(target)
    test_cases = generator.generate_all(points, method, body_params)
    
    return [
        {
            "injection_point": tc.injection_point,
            "payload": tc.payload["payload"],
            "raw_request": tc.raw_request,
        }
        for tc in test_cases
    ]