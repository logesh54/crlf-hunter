"""
Advanced Response Analyzer with Differential Analysis and Timing Detection
Professional-grade vulnerability detection for CRLF injection and response splitting
"""

import re
import hashlib
import difflib
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter
import json


class VulnerabilityType(Enum):
    """Types of vulnerabilities detected"""
    CRLF_INJECTION = "crlf_injection"
    RESPONSE_SPLITTING = "response_splitting"
    HEADER_INJECTION = "header_injection"
    COOKIE_INJECTION = "cookie_injection"
    CACHE_POISONING = "cache_poisoning"
    XSS_VIA_SPLITTING = "xss_via_splitting"
    REQUEST_SMUGGLING = "request_smuggling"
    OPEN_REDIRECT = "open_redirect"
    REFLECTION_ONLY = "reflection_only"
    FALSE_POSITIVE = "false_positive"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    """Confidence level of detection"""
    CONFIRMED = "confirmed"      # Clear evidence
    HIGH = "high"                # Strong indicators
    MEDIUM = "medium"            # Some indicators
    LOW = "low"                  # Weak indicators
    INFO = "info"                # Informational only


@dataclass
class Evidence:
    """Evidence of vulnerability"""
    type: str
    description: str
    raw_snippet: str
    location: str  # header, body, status_line
    confidence: ConfidenceLevel
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "description": self.description,
            "raw_snippet": self.raw_snippet[:500],  # Limit size
            "location": self.location,
            "confidence": self.confidence.value,
            "metadata": self.metadata,
        }


@dataclass
class AnalysisResult:
    """Result of response analysis"""
    vulnerable: bool
    vulnerability_type: VulnerabilityType
    confidence: ConfidenceLevel
    evidences: List[Evidence] = field(default_factory=list)
    marker_found: bool = False
    marker_locations: List[str] = field(default_factory=list)
    response_hash: str = ""
    diff_score: float = 0.0
    timing_anomaly: bool = False
    baseline_comparison: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "vulnerable": self.vulnerable,
            "vulnerability_type": self.vulnerability_type.value,
            "confidence": self.confidence.value,
            "evidences": [e.to_dict() for e in self.evidences],
            "marker_found": self.marker_found,
            "marker_locations": self.marker_locations,
            "response_hash": self.response_hash,
            "diff_score": self.diff_score,
            "timing_anomaly": self.timing_anomaly,
            "baseline_comparison": self.baseline_comparison,
            "metadata": self.metadata,
        }


class ResponseParser:
    """Parse raw HTTP response into structured components"""
    
    @staticmethod
    def parse(raw_response: bytes) -> Dict[str, Any]:
        """Parse response into components"""
        result = {
            "raw": raw_response,
            "status_line": "",
            "status_code": 0,
            "http_version": "",
            "headers": {},
            "headers_raw": b"",
            "body": b"",
            "body_text": "",
            "header_end_pos": -1,
            "is_chunked": False,
            "content_length": None,
            "content_type": "",
            "server": "",
            "cookies": [],
        }
        
        if not raw_response:
            return result
        
        # Find header/body boundary
        header_end = raw_response.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = raw_response.find(b"\n\n")
        
        if header_end == -1:
            result["headers_raw"] = raw_response
            result["body"] = b""
        else:
            result["headers_raw"] = raw_response[:header_end]
            result["body"] = raw_response[header_end + 4:]
            result["header_end_pos"] = header_end
        
        # Parse headers
        header_text = result["headers_raw"].decode("utf-8", errors="ignore")
        lines = header_text.split("\r\n")
        if not lines:
            lines = header_text.split("\n")
        
        if lines:
            result["status_line"] = lines[0].strip()
            # Parse status line
            parts = result["status_line"].split()
            if len(parts) >= 2:
                result["http_version"] = parts[0]
                try:
                    result["status_code"] = int(parts[1])
                except ValueError:
                    pass
            
            # Parse header fields
            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip().lower()
                    val = val.strip()
                    result["headers"][key] = val
                    
                    # Special headers
                    if key == "set-cookie":
                        result["cookies"].append(val)
                    elif key == "content-length":
                        try:
                            result["content_length"] = int(val)
                        except ValueError:
                            pass
                    elif key == "content-type":
                        result["content_type"] = val
                    elif key == "server":
                        result["server"] = val
                    elif key == "transfer-encoding":
                        result["is_chunked"] = "chunked" in val.lower()
        
        # Body text
        result["body_text"] = result["body"].decode("utf-8", errors="ignore")
        
        return result
    
    @staticmethod
    def count_status_lines(raw_response: bytes) -> int:
        """Count HTTP status lines in response"""
        pattern = rb'HTTP/\d\.\d\s+\d{3}'
        return len(re.findall(pattern, raw_response))
    
    @staticmethod
    def extract_headers_section(raw_response: bytes) -> bytes:
        """Extract just the headers section"""
        header_end = raw_response.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = raw_response.find(b"\n\n")
        if header_end == -1:
            return raw_response
        return raw_response[:header_end + 4]


class DifferentialAnalyzer:
    """Compare responses to detect anomalies"""
    
    def __init__(self):
        self.baselines: Dict[str, Dict] = {}  # key -> baseline response info
    
    def set_baseline(self, key: str, raw_response: bytes, timing: float = 0):
        """Store baseline response for comparison"""
        parsed = ResponseParser.parse(raw_response)
        self.baselines[key] = {
            "hash": self._hash_response(parsed),
            "status_code": parsed["status_code"],
            "headers": parsed["headers"].copy(),
            "header_count": len(parsed["headers"]),
            "body_length": len(parsed["body"]),
            "body_hash": hashlib.md5(parsed["body"]).hexdigest(),
            "timing": timing,
            "status_lines": ResponseParser.count_status_lines(raw_response),
        }
    
    def compare(self, key: str, raw_response: bytes, timing: float = 0) -> Dict[str, Any]:
        """Compare response against baseline"""
        if key not in self.baselines:
            return {"error": "No baseline available"}
        
        baseline = self.baselines[key]
        parsed = ResponseParser.parse(raw_response)
        
        current_hash = self._hash_response(parsed)
        
        comparison = {
            "hash_changed": current_hash != baseline["hash"],
            "status_code_changed": parsed["status_code"] != baseline["status_code"],
            "status_code": parsed["status_code"],
            "baseline_status_code": baseline["status_code"],
            "header_count_diff": len(parsed["headers"]) - baseline["header_count"],
            "new_headers": [],
            "missing_headers": [],
            "changed_headers": [],
            "body_length_diff": len(parsed["body"]) - baseline["body_length"],
            "body_changed": hashlib.md5(parsed["body"]).hexdigest() != baseline["body_hash"],
            "timing_diff": timing - baseline["timing"] if baseline["timing"] else 0,
            "status_lines": ResponseParser.count_status_lines(raw_response),
            "baseline_status_lines": baseline["status_lines"],
            "additional_status_lines": ResponseParser.count_status_lines(raw_response) - baseline["status_lines"],
        }
        
        # Find header differences
        baseline_headers = set(baseline["headers"].keys())
        current_headers = set(parsed["headers"].keys())
        
        comparison["new_headers"] = list(current_headers - baseline_headers)
        comparison["missing_headers"] = list(baseline_headers - current_headers)
        
        # Check changed header values
        for h in baseline_headers & current_headers:
            if baseline["headers"][h] != parsed["headers"][h]:
                comparison["changed_headers"].append({
                    "header": h,
                    "baseline": baseline["headers"][h][:100],
                    "current": parsed["headers"][h][:100],
                })
        
        # Calculate similarity score
        comparison["similarity_score"] = self._calculate_similarity(baseline, parsed)
        
        return comparison
    
    def _hash_response(self, parsed: Dict) -> str:
        """Create hash of response structure"""
        h = hashlib.md5()
        h.update(str(parsed["status_code"]).encode())
        for k in sorted(parsed["headers"].keys()):
            h.update(k.encode())
            h.update(parsed["headers"][k].encode())
        h.update(str(len(parsed["body"])).encode())
        return h.hexdigest()
    
    def _calculate_similarity(self, baseline: Dict, parsed: Dict) -> float:
        """Calculate similarity score (0-1)"""
        score = 1.0
        
        # Status code
        if baseline["status_code"] != parsed["status_code"]:
            score -= 0.3
        
        # Headers
        baseline_h = set(baseline["headers"].keys())
        current_h = set(parsed["headers"].keys())
        if baseline_h:
            header_similarity = len(baseline_h & current_h) / len(baseline_h | current_h)
            score *= header_similarity
        
        # Body length
        if baseline["body_length"] > 0:
            length_ratio = min(parsed["body_length"], baseline["body_length"]) / max(parsed["body_length"], baseline["body_length"])
            score *= length_ratio
        
        return max(0.0, min(1.0, score))


class TimingAnalyzer:
    """Analyze response timing for anomalies"""
    
    def __init__(self, threshold_multiplier: float = 3.0, min_samples: int = 5):
        self.threshold_multiplier = threshold_multiplier
        self.min_samples = min_samples
        self.samples: List[float] = []
        self.baseline_avg: float = 0
        self.baseline_std: float = 0
    
    def add_sample(self, timing: float):
        """Add timing sample"""
        self.samples.append(timing)
        if len(self.samples) >= self.min_samples:
            self._recalculate_baseline()
    
    def _recalculate_baseline(self):
        """Recalculate baseline statistics"""
        if len(self.samples) < 2:
            return
        
        self.baseline_avg = sum(self.samples) / len(self.samples)
        variance = sum((x - self.baseline_avg) ** 2 for x in self.samples) / len(self.samples)
        self.baseline_std = variance ** 0.5
    
    def is_anomaly(self, timing: float) -> Tuple[bool, float]:
        """Check if timing is anomalous"""
        if self.baseline_std == 0:
            return False, 0.0
        
        z_score = abs(timing - self.baseline_avg) / self.baseline_std
        is_anomaly = z_score > self.threshold_multiplier
        
        return is_anomaly, z_score
    
    def get_stats(self) -> Dict:
        return {
            "samples": len(self.samples),
            "avg": self.baseline_avg,
            "std": self.baseline_std,
            "threshold": self.baseline_avg + self.threshold_multiplier * self.baseline_std,
        }


class AdvancedAnalyzer:
    """Main analyzer with all detection capabilities"""
    
    def __init__(
        self,
        marker: str = None,
        enable_differential: bool = True,
        enable_timing: bool = True,
        confidence_threshold: ConfidenceLevel = ConfidenceLevel.MEDIUM,
    ):
        self.marker = marker or "crlfhunter_poc"
        self.enable_differential = enable_differential
        self.enable_timing = enable_timing
        self.confidence_threshold = confidence_threshold
        
        self.differential = DifferentialAnalyzer()
        self.timing = TimingAnalyzer()
        
        # Compile regex patterns
        self.patterns = {
            "status_line": re.compile(rb'HTTP/\d\.\d\s+\d{3}'),
            "set_cookie": re.compile(rb'Set-Cookie:\s*([^;\r\n]+)', re.IGNORECASE),
            "location": re.compile(rb'Location:\s*([^\r\n]+)', re.IGNORECASE),
            "xss_script": re.compile(rb'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            "xss_event": re.compile(rb'on\w+\s*=', re.IGNORECASE),
            "php_errors": re.compile(rb'(Warning|Fatal error|Parse error|Notice):', re.IGNORECASE),
            "sql_errors": re.compile(rb'(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL|SQLite)', re.IGNORECASE),
            "stack_trace": re.compile(rb'(Traceback|at \w+\.\w+\(|File ")', re.IGNORECASE),
        }
    
    def analyze(
        self,
        raw_response: bytes,
        raw_request: bytes = b"",
        marker: str = None,
        baseline_key: str = None,
        timing: float = 0,
        injection_point: str = "",
        payload_info: Dict = None,
    ) -> AnalysisResult:
        """Main analysis function"""
        marker = marker or self.marker
        parsed = ResponseParser.parse(raw_response)
        
        result = AnalysisResult(
            vulnerable=False,
            vulnerability_type=VulnerabilityType.UNKNOWN,
            confidence=ConfidenceLevel.INFO,
            response_hash=self._hash_response(parsed),
        )
        
        # Check for marker
        marker_bytes = marker.encode()
        marker_found, marker_locations = self._find_marker(parsed, marker_bytes)
        result.marker_found = marker_found
        result.marker_locations = marker_locations
        
        # Differential analysis
        if self.enable_differential and baseline_key:
            diff = self.differential.compare(baseline_key, raw_response, timing)
            result.baseline_comparison = diff
            result.diff_score = 1.0 - diff.get("similarity_score", 1.0)
            
            # Check for new headers (injection indicator)
            if diff.get("new_headers"):
                for h in diff["new_headers"]:
                    if marker.lower() in h.lower():
                        result.evidences.append(Evidence(
                            type="header_injection",
                            description=f"Marker found in new header: {h}",
                            raw_snippet=f"{h}: {parsed['headers'].get(h, '')}",
                            location="header",
                            confidence=ConfidenceLevel.HIGH,
                        ))
                        result.vulnerable = True
                        result.vulnerability_type = VulnerabilityType.HEADER_INJECTION
                        result.confidence = ConfidenceLevel.HIGH
        
        # Timing analysis
        if self.enable_timing:
            is_anomaly, z_score = self.timing.is_anomaly(timing)
            result.timing_anomaly = is_anomaly
            result.metadata["timing_z_score"] = z_score
            if is_anomaly:
                result.evidences.append(Evidence(
                    type="timing_anomaly",
                    description=f"Response time anomaly (z-score: {z_score:.2f})",
                    raw_snippet=f"Timing: {timing:.3f}s",
                    location="timing",
                    confidence=ConfidenceLevel.LOW,
                    metadata={"z_score": z_score, "baseline_avg": self.timing.baseline_avg},
                ))
        
        # Core vulnerability checks
        self._check_response_splitting(parsed, raw_response, result)
        self._check_header_injection(parsed, marker, result)
        self._check_cookie_injection(parsed, marker, result)
        self._check_cache_poisoning(parsed, marker, result)
        self._check_xss_via_splitting(parsed, marker, result)
        self._check_request_smuggling(parsed, raw_response, result)
        self._check_open_redirect(parsed, marker, result)
        self._check_reflection_only(parsed, marker, result)
        self._check_error_disclosure(parsed, result)
        
        # Determine final verdict
        self._finalize_result(result)
        
        return result
    
    def _find_marker(self, parsed: Dict, marker_bytes: bytes) -> Tuple[bool, List[str]]:
        """Find marker in response"""
        locations = []
        
        # Check status line
        if marker_bytes in parsed["status_line"].encode():
            locations.append("status_line")
        
        # Check headers
        for k, v in parsed["headers"].items():
            if marker_bytes in k.encode() or marker_bytes in v.encode():
                locations.append(f"header:{k}")
        
        # Check cookies
        for cookie in parsed["cookies"]:
            if marker_bytes in cookie.encode():
                locations.append("cookie")
        
        # Check body
        if marker_bytes in parsed["body"]:
            locations.append("body")
        
        return len(locations) > 0, locations
    
    def _check_response_splitting(self, parsed: Dict, raw: bytes, result: AnalysisResult):
        """Check for HTTP response splitting"""
        status_count = ResponseParser.count_status_lines(raw)
        
        if status_count > 1:
            # Multiple status lines = response splitting
            matches = list(self.patterns["status_line"].finditer(raw))
            if len(matches) >= 2:
                second_status = raw[matches[1].start():matches[1].start() + 200]
                result.evidences.append(Evidence(
                    type="response_splitting",
                    description=f"Multiple HTTP status lines detected ({status_count})",
                    raw_snippet=second_status.decode("utf-8", errors="ignore"),
                    location="status_line",
                    confidence=ConfidenceLevel.CONFIRMED,
                    metadata={"status_line_count": status_count},
                ))
                result.vulnerable = True
                result.vulnerability_type = VulnerabilityType.RESPONSE_SPLITTING
                result.confidence = ConfidenceLevel.CONFIRMED
    
    def _check_header_injection(self, parsed: Dict, marker: str, result: AnalysisResult):
        """Check for header injection"""
        marker_lower = marker.lower()
        
        for k, v in parsed["headers"].items():
            if marker_lower in k.lower() or marker_lower in v.lower():
                # Check if it's a real header (not in body)
                result.evidences.append(Evidence(
                    type="header_injection",
                    description=f"Marker found in response header: {k}",
                    raw_snippet=f"{k}: {v}",
                    location="header",
                    confidence=ConfidenceLevel.CONFIRMED,
                    metadata={"header": k, "value": v[:200]},
                ))
                
                if result.vulnerability_type == VulnerabilityType.UNKNOWN:
                    result.vulnerability_type = VulnerabilityType.HEADER_INJECTION
                
                result.vulnerable = True
                result.confidence = ConfidenceLevel.CONFIRMED
    
    def _check_cookie_injection(self, parsed: Dict, marker: str, result: AnalysisResult):
        """Check for cookie injection via Set-Cookie"""
        marker_lower = marker.lower()
        
        for cookie in parsed["cookies"]:
            if marker_lower in cookie.lower():
                result.evidences.append(Evidence(
                    type="cookie_injection",
                    description="Marker found in Set-Cookie header",
                    raw_snippet=f"Set-Cookie: {cookie}",
                    location="header",
                    confidence=ConfidenceLevel.CONFIRMED,
                    metadata={"cookie": cookie[:200]},
                ))
                
                if result.vulnerability_type in [VulnerabilityType.UNKNOWN, VulnerabilityType.HEADER_INJECTION]:
                    result.vulnerability_type = VulnerabilityType.COOKIE_INJECTION
                
                result.vulnerable = True
                result.confidence = ConfidenceLevel.CONFIRMED
    
    def _check_cache_poisoning(self, parsed: Dict, marker: str, result: AnalysisResult):
        """Check for cache poisoning indicators"""
        marker_lower = marker.lower()
        
        # Location header with marker
        location = parsed["headers"].get("location", "")
        if marker_lower in location.lower():
            result.evidences.append(Evidence(
                type="cache_poisoning",
                description="Marker found in Location header (cache poisoning vector)",
                raw_snippet=f"Location: {location}",
                location="header",
                confidence=ConfidenceLevel.HIGH,
                metadata={"location": location},
            ))
            
            if result.vulnerability_type == VulnerabilityType.UNKNOWN:
                result.vulnerability_type = VulnerabilityType.CACHE_POISONING
            
            result.vulnerable = True
            result.confidence = max(result.confidence, ConfidenceLevel.HIGH)
        
        # Cache control headers with marker
        for h in ["cache-control", "expires", "etag", "vary"]:
            val = parsed["headers"].get(h, "")
            if marker_lower in val.lower():
                result.evidences.append(Evidence(
                    type="cache_poisoning",
                    description=f"Marker found in cache header: {h}",
                    raw_snippet=f"{h}: {val}",
                    location="header",
                    confidence=ConfidenceLevel.MEDIUM,
                ))
    
    def _check_xss_via_splitting(self, parsed: Dict, marker: str, result: AnalysisResult):
        """Check for XSS via response splitting"""
        marker_lower = marker.lower()
        body_lower = parsed["body_text"].lower()
        
        # Check if marker appears in body with script tags
        if marker_lower in body_lower:
            # Look for script tags near marker
            marker_pos = body_lower.find(marker_lower)
            context = parsed["body_text"][max(0, marker_pos-200):marker_pos+200]
            
            if self.patterns["xss_script"].search(context.encode()) or \
               self.patterns["xss_event"].search(context.encode()):
                result.evidences.append(Evidence(
                    type="xss_via_splitting",
                    description="Potential XSS via response splitting - script tags near marker",
                    raw_snippet=context[:500],
                    location="body",
                    confidence=ConfidenceLevel.HIGH,
                ))
                
                if result.vulnerability_type == VulnerabilityType.UNKNOWN:
                    result.vulnerability_type = VulnerabilityType.XSS_VIA_SPLITTING
                
                result.vulnerable = True
                result.confidence = max(result.confidence, ConfidenceLevel.HIGH)
    
    def _check_request_smuggling(self, parsed: Dict, raw: bytes, result: AnalysisResult):
        """Check for request smuggling indicators"""
        # Look for indicators in response that suggest smuggling worked
        # e.g., unexpected status codes, missing headers, etc.
        
        # Check for 400/500 errors that might indicate parsing issues
        if parsed["status_code"] in [400, 500, 502, 503]:
            # Could be smuggling attempt causing parse error
            pass
        
        # Check for multiple Content-Length or Transfer-Encoding
        cl_count = sum(1 for k in parsed["headers"] if k == "content-length")
        te_count = sum(1 for k in parsed["headers"] if k == "transfer-encoding")
        
        if cl_count > 1 or te_count > 1:
            result.evidences.append(Evidence(
                type="request_smuggling",
                description="Duplicate Content-Length or Transfer-Encoding headers",
                raw_snippet=json.dumps({k: parsed["headers"][k] for k in parsed["headers"] 
                                         if k in ["content-length", "transfer-encoding"]}),
                location="header",
                confidence=ConfidenceLevel.MEDIUM,
            ))
    
    def _check_open_redirect(self, parsed: Dict, marker: str, result: AnalysisResult):
        """Check for open redirect via header injection"""
        marker_lower = marker.lower()
        location = parsed["headers"].get("location", "")
        
        if location and marker_lower in location.lower():
            # Check if it's redirecting to external domain
            if "evil" in location.lower() or "attacker" in location.lower() or marker in location:
                result.evidences.append(Evidence(
                    type="open_redirect",
                    description="Open redirect via injected Location header",
                    raw_snippet=f"Location: {location}",
                    location="header",
                    confidence=ConfidenceLevel.HIGH,
                ))
                
                if result.vulnerability_type == VulnerabilityType.UNKNOWN:
                    result.vulnerability_type = VulnerabilityType.OPEN_REDIRECT
                
                result.vulnerable = True
                result.confidence = max(result.confidence, ConfidenceLevel.HIGH)
    
    def _check_reflection_only(self, parsed: Dict, marker: str, result: AnalysisResult):
        """Check if marker only reflected in body (not a vulnerability)"""
        marker_lower = marker.lower()
        
        # Only check if no vulnerability has been confirmed yet
        if result.vulnerable:
            return
        
        # If marker only in body and no other vulnerabilities found
        if (marker_lower in parsed["body_text"].lower() and 
            (not result.marker_locations or all(loc == "body" for loc in result.marker_locations))):
            
            # Verify it's not in headers
            in_headers = any(
                marker_lower in k.lower() or marker_lower in v.lower() 
                for k, v in parsed["headers"].items()
            )
            
            if not in_headers:
                result.evidences.append(Evidence(
                    type="reflection_only",
                    description="Marker only reflected in response body (not injected)",
                    raw_snippet=self._get_marker_context(parsed["body_text"], marker),
                    location="body",
                    confidence=ConfidenceLevel.INFO,
                ))
                
                result.vulnerability_type = VulnerabilityType.REFLECTION_ONLY
                result.vulnerable = False
                result.confidence = ConfidenceLevel.INFO
    
    def _check_error_disclosure(self, parsed: Dict, result: AnalysisResult):
        """Check for error disclosure in response"""
        body_text = parsed["body_text"]
        
        for error_type, pattern in [
            ("php", self.patterns["php_errors"]),
            ("sql", self.patterns["sql_errors"]),
            ("stack_trace", self.patterns["stack_trace"]),
        ]:
            matches = pattern.findall(body_text.encode())
            if matches:
                result.evidences.append(Evidence(
                    type="error_disclosure",
                    description=f"{error_type.upper()} error disclosure detected",
                    raw_snippet=matches[0].decode("utf-8", errors="ignore")[:200],
                    location="body",
                    confidence=ConfidenceLevel.LOW,
                    metadata={"error_type": error_type, "count": len(matches)},
                ))
    
    def _get_marker_context(self, text: str, marker: str, context_size: int = 100) -> str:
        """Get context around marker in text"""
        pos = text.lower().find(marker.lower())
        if pos == -1:
            return ""
        start = max(0, pos - context_size)
        end = min(len(text), pos + len(marker) + context_size)
        return text[start:end]
    
    def _finalize_result(self, result: AnalysisResult):
        """Finalize analysis result"""
        # If no vulnerability found but marker in body only
        if not result.vulnerable and result.marker_found:
            if all(loc == "body" for loc in result.marker_locations):
                result.vulnerability_type = VulnerabilityType.REFLECTION_ONLY
                result.confidence = ConfidenceLevel.INFO
        
        # Adjust confidence based on evidence count
        if result.vulnerable:
            confirmed_count = sum(1 for e in result.evidences if e.confidence == ConfidenceLevel.CONFIRMED)
            high_count = sum(1 for e in result.evidences if e.confidence == ConfidenceLevel.HIGH)
            
            if confirmed_count > 0:
                result.confidence = ConfidenceLevel.CONFIRMED
            elif high_count > 0:
                result.confidence = ConfidenceLevel.HIGH
            elif len(result.evidences) > 1:
                result.confidence = ConfidenceLevel.MEDIUM
    
    def _hash_response(self, parsed: Dict) -> str:
        """Hash response for comparison"""
        h = hashlib.md5()
        h.update(str(parsed["status_code"]).encode())
        for k in sorted(parsed["headers"].keys()):
            h.update(k.encode())
            h.update(parsed["headers"][k].encode())
        h.update(str(len(parsed["body"])).encode())
        return h.hexdigest()[:16]
    
    def analyze_batch(
        self,
        responses: List[Tuple[bytes, bytes, str, Dict]],  # (request, response, marker, payload_info)
        baseline_responses: Dict[str, bytes] = None,
    ) -> List[AnalysisResult]:
        """Analyze multiple responses"""
        results = []
        
        # Set baselines if provided
        if baseline_responses:
            for key, resp in baseline_responses.items():
                self.differential.set_baseline(key, resp)
        
        for i, (request, response, marker, payload_info) in enumerate(responses):
            baseline_key = None
            if baseline_responses:
                baseline_key = list(baseline_responses.keys())[i % len(baseline_responses)]
            
            result = self.analyze(
                raw_response=response,
                raw_request=request,
                marker=marker,
                baseline_key=baseline_key,
                injection_point=payload_info.get("injection_point", ""),
                payload_info=payload_info,
            )
            results.append(result)
        
        return results


# Legacy compatibility
def parse_http_response(raw_response: bytes) -> Tuple[str, Dict, bytes, bytes]:
    """Legacy function"""
    parsed = ResponseParser.parse(raw_response)
    return (
        parsed["status_line"],
        parsed["headers"],
        parsed["body"],
        parsed["headers_raw"],
    )


def count_status_lines(raw_response: bytes) -> int:
    """Legacy function"""
    return ResponseParser.count_status_lines(raw_response)


def check_marker_in_headers(headers: Dict, marker: str) -> Tuple[bool, str]:
    """Legacy function"""
    marker_lower = marker.lower()
    for k, v in headers.items():
        if marker_lower in k.lower() or marker_lower in v.lower():
            return True, f"{k}: {v}"
    return False, None


def check_marker_in_set_cookie(headers: Dict, marker: str) -> Tuple[bool, str]:
    """Legacy function"""
    marker_lower = marker.lower()
    for k, v in headers.items():
        if k.lower() == "set-cookie" and marker_lower in v.lower():
            return True, f"{k}: {v}"
    return False, None


def analyze_response(raw_response: bytes, marker: str = None) -> Tuple[bool, str, str]:
    """Legacy function"""
    marker = marker or "crlfhunter_poc"
    analyzer = AdvancedAnalyzer(marker=marker)
    result = analyzer.analyze(raw_response, marker=marker)
    evidence = result.evidences[0].raw_snippet if result.evidences else "no_indicators_found"
    return result.vulnerable, evidence, result.vulnerability_type.value


def extract_evidence_snippet(raw_response: bytes, max_len: int = 200) -> str:
    """Legacy function"""
    return raw_response[:max_len].decode("utf-8", errors="ignore")


# Import hashlib
import hashlib