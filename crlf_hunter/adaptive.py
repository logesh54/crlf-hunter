"""
Rate limit detection and WAF fingerprinting
Automatically detects rate limiting and WAF presence, adjusts scan behavior
"""

import re
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import threading


class RateLimitAction(Enum):
    """Actions to take when rate limited"""
    WAIT = "wait"
    REDUCE_CONCURRENCY = "reduce_concurrency"
    INCREASE_DELAY = "increase_delay"
    PAUSE = "pause"
    ABORT = "abort"


class WAFType(Enum):
    """Known WAF types"""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    F5_BIGIP = "f5_bigip"
    MODSECURITY = "modsecurity"
    SUCURI = "sucuri"
    WALLARM = "wallarm"
    REBLAZE = "reblaxe"
    UNKNOWN = "unknown"


@dataclass
class RateLimitInfo:
    """Information about detected rate limiting"""
    detected: bool = False
    limit: int = 0
    window: int = 0  # seconds
    remaining: int = 0
    reset_time: float = 0
    headers: Dict[str, str] = field(default_factory=dict)
    action: RateLimitAction = RateLimitAction.WAIT
    confidence: float = 0.0


@dataclass
class WAFInfo:
    """Information about detected WAF"""
    detected: bool = False
    waf_type: WAFType = WAFType.UNKNOWN
    version: str = ""
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    behavior_notes: List[str] = field(default_factory=list)


class RateLimitDetector:
    """Detects and handles rate limiting"""
    
    # Common rate limit headers
    RATE_LIMIT_HEADERS = {
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "x-rate-limit-limit",
        "x-rate-limit-remaining",
        "x-rate-limit-reset",
        "retry-after",
    }
    
    # Rate limit status codes
    RATE_LIMIT_CODES = {429, 503, 509}
    
    def __init__(self, 
                 max_concurrency: int = 10,
                 min_concurrency: int = 1,
                 base_delay: float = 0.5,
                 max_delay: float = 30.0):
        self.max_concurrency = max_concurrency
        self.min_concurrency = min_concurrency
        self.current_concurrency = max_concurrency
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.max_delay = max_delay
        
        # History for adaptive behavior
        self.response_history: deque = deque(maxlen=100)
        self.rate_limit_events: List[Tuple[float, RateLimitInfo]] = []
        
        self._lock = threading.Lock()
    
    def analyze_response(self, status_code: int, headers: Dict[str, str], 
                        response_time: float) -> RateLimitInfo:
        """Analyze response for rate limiting indicators"""
        info = RateLimitInfo()
        
        # Check status code
        if status_code in self.RATE_LIMIT_CODES:
            info.detected = True
            info.confidence = 0.9
            info.action = RateLimitAction.REDUCE_CONCURRENCY
        
        # Check rate limit headers
        header_info = {}
        for h in self.RATE_LIMIT_HEADERS:
            if h in headers:
                header_info[h] = headers[h]
        
        if header_info:
            info.headers = header_info
            info.detected = True
            info.confidence = max(info.confidence, 0.8)
            
            # Parse limit info
            try:
                if "x-ratelimit-limit" in headers:
                    info.limit = int(headers["x-ratelimit-limit"])
                elif "ratelimit-limit" in headers:
                    info.limit = int(headers["ratelimit-limit"])
                
                if "x-ratelimit-remaining" in headers:
                    info.remaining = int(headers["x-ratelimit-remaining"])
                elif "ratelimit-remaining" in headers:
                    info.remaining = int(headers["ratelimit-remaining"])
                
                if "x-ratelimit-reset" in headers:
                    info.reset_time = float(headers["x-ratelimit-reset"])
                elif "ratelimit-reset" in headers:
                    info.reset_time = float(headers["ratelimit-reset"])
                elif "retry-after" in headers:
                    info.reset_time = time.time() + float(headers["retry-after"])
            except (ValueError, TypeError):
                pass
            
            # Determine action based on remaining
            if info.remaining == 0:
                info.action = RateLimitAction.PAUSE
            elif info.remaining is not None and info.remaining < 10:
                info.action = RateLimitAction.REDUCE_CONCURRENCY
        
        # Check for rate limit patterns in response body (would need body)
        # This is a placeholder for body analysis
        
        # Record event
        with self._lock:
            self.rate_limit_events.append((time.time(), info))
            self.response_history.append({
                "time": time.time(),
                "status": status_code,
                "rate_limited": info.detected,
                "response_time": response_time,
            })
        
        return info
    
    def get_recommended_action(self) -> Tuple[RateLimitAction, Dict]:
        """Get recommended action based on recent history"""
        with self._lock:
            recent = [e for e in self.rate_limit_events if time.time() - e[0] < 60]
            recent_responses = [r for r in self.response_history if time.time() - r["time"] < 60]
        
        if not recent:
            return RateLimitAction.WAIT, {}
        
        rate_limited_count = sum(1 for _, info in recent if info.detected)
        total_recent = len(recent)
        
        if total_recent == 0:
            return RateLimitAction.WAIT, {}
        
        rate_limit_ratio = rate_limited_count / total_recent
        
        if rate_limit_ratio > 0.5:
            return RateLimitAction.PAUSE, {"reason": "High rate limit ratio"}
        elif rate_limit_ratio > 0.2:
            return RateLimitAction.REDUCE_CONCURRENCY, {"reason": "Moderate rate limit ratio"}
        elif rate_limit_ratio > 0.1:
            return RateLimitAction.INCREASE_DELAY, {"reason": "Low rate limit ratio"}
        
        return RateLimitAction.WAIT, {}
    
    def apply_action(self, action: RateLimitAction) -> Dict[str, Any]:
        """Apply rate limit action and return new settings"""
        changes = {}
        
        if action == RateLimitAction.REDUCE_CONCURRENCY:
            new_concurrency = max(self.min_concurrency, self.current_concurrency // 2)
            if new_concurrency != self.current_concurrency:
                changes["concurrency"] = new_concurrency
                self.current_concurrency = new_concurrency
        
        elif action == RateLimitAction.INCREASE_DELAY:
            new_delay = min(self.max_delay, self.current_delay * 2)
            if new_delay != self.current_delay:
                changes["delay"] = new_delay
                self.current_delay = new_delay
        
        elif action == RateLimitAction.PAUSE:
            changes["pause"] = True
        
        return changes
    
    def reset(self):
        """Reset to default settings"""
        with self._lock:
            self.current_concurrency = self.max_concurrency
            self.current_delay = self.base_delay
            self.rate_limit_events.clear()
            self.response_history.clear()
    
    def get_stats(self) -> Dict:
        """Get detector statistics"""
        with self._lock:
            return {
                "current_concurrency": self.current_concurrency,
                "current_delay": self.current_delay,
                "rate_limit_events": len(self.rate_limit_events),
                "recent_rate_limited": sum(1 for _, info in self.rate_limit_events 
                                           if time.time() - _ < 60 and info.detected),
            }


# WAF Fingerprinting
class WAFFingerprinter:
    """Detects and identifies Web Application Firewalls"""
    
    # WAF signatures
    WAF_SIGNATURES = {
        WAFType.CLOUDFLARE: {
            "headers": ["cf-ray", "cf-cache-status", "__cf_bm", "cf-mitigated"],
            "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
            "body_patterns": [
                r"cloudflare",
                r"ray id:",
                r"attention required! \| cloudflare",
                r"checking your browser before accessing",
            ],
            "status_codes": [403, 503],
        },
        WAFType.AWS_WAF: {
            "headers": ["x-amzn-waf", "x-amzn-requestid"],
            "cookies": ["aws-waf-token"],
            "body_patterns": [
                r"aws.*waf",
                r"request blocked",
                r"the request could not be satisfied",
            ],
            "status_codes": [403, 503],
        },
        WAFType.AKAMAI: {
            "headers": ["akamai-origin-hop", "x-akamai-transformed", "akamai-g-host"],
            "cookies": ["ak_bmsc", "bm_sv", "akamai_session"],
            "body_patterns": [
                r"akamai",
                r"access denied",
                r"reference #",
            ],
            "status_codes": [403, 503],
        },
        WAFType.IMPERVA: {
            "headers": ["x-iinfo", "x-cdn", "imperva"],
            "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
            "body_patterns": [
                r"imperva",
                r"incapsula",
                r"request unsuccessful",
                r"incident id:",
            ],
            "status_codes": [403, 503],
        },
        WAFType.F5_BIGIP: {
            "headers": ["x-wa-info", "x-f5", "bigip"],
            "cookies": ["bigipserver", "ts", "mrhd"],
            "body_patterns": [
                r"f5 networks",
                r"big-ip",
                r"the requested url was rejected",
                r"request rejected",
            ],
            "status_codes": [403, 503],
        },
        WAFType.MODSECURITY: {
            "headers": ["mod_security", "modsecurity"],
            "cookies": [],
            "body_patterns": [
                r"mod_security",
                r"modsecurity",
                r"this error was generated by mod_security",
                r"anomaly score",
                r"owasp_crs",
            ],
            "status_codes": [403, 500, 501, 503],
        },
        WAFType.SUCURI: {
            "headers": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
            "cookies": ["sucuri_cloudproxy_uuid"],
            "body_patterns": [
                r"sucuri",
                r"cloudproxy",
                r"access denied - sucuri",
            ],
            "status_codes": [403, 503],
        },
        WAFType.WALLARM: {
            "headers": ["x-wallarm", "x-wallarm-attack"],
            "cookies": [],
            "body_patterns": [
                r"wallarm",
                r"blocked by wallarm",
            ],
            "status_codes": [403, 503],
        },
    }
    
    def __init__(self):
        self.detected_wafs: List[WAFInfo] = []
        self._lock = threading.Lock()
    
    def analyze(self, status_code: int, headers: Dict[str, str], 
                body: str = "", cookies: Dict[str, str] = None) -> List[WAFInfo]:
        """Analyze response for WAF indicators"""
        cookies = cookies or {}
        detected = []
        
        for waf_type, signatures in self.WAF_SIGNATURES.items():
            info = WAFInfo()
            info.waf_type = waf_type
            indicators = []
            confidence = 0.0
            
            # Check headers
            for header in signatures["headers"]:
                for h, v in headers.items():
                    if header.lower() in h.lower():
                        indicators.append(f"Header: {h} = {v}")
                        info.headers[h] = v
                        confidence += 0.3
            
            # Check cookies
            for cookie_pattern in signatures["cookies"]:
                for cookie_name in cookies:
                    if cookie_pattern in cookie_name:
                        indicators.append(f"Cookie: {cookie_name}")
                        info.cookies[cookie_name] = cookies[cookie_name]
                        confidence += 0.2
            
            # Check body patterns
            for pattern in signatures["body_patterns"]:
                if re.search(pattern, body, re.IGNORECASE):
                    indicators.append(f"Body pattern: {pattern}")
                    confidence += 0.4
            
            # Check status codes
            if status_code in signatures["status_codes"]:
                confidence += 0.1
            
            if confidence > 0.3:
                info.detected = True
                info.confidence = min(confidence, 1.0)
                info.indicators = indicators
                info.status_codes = [status_code]
                
                detected.append(info)
        
        with self._lock:
            # Deduplicate - keep highest confidence for each type
            existing_types = {w.waf_type: w for w in self.detected_wafs}
            for info in detected:
                if info.waf_type not in existing_types or info.confidence > existing_types[info.waf_type].confidence:
                    existing_types[info.waf_type] = info
            self.detected_wafs = list(existing_types.values())
        
        return detected
    
    def get_detected_wafs(self) -> List[WAFInfo]:
        """Get all detected WAFs"""
        with self._lock:
            return self.detected_wafs.copy()
    
    def get_primary_waf(self) -> Optional[WAFInfo]:
        """Get the most confidently detected WAF"""
        with self._lock:
            if not self.detected_wafs:
                return None
            return max(self.detected_wafs, key=lambda w: w.confidence)
    
    def get_evasion_recommendations(self) -> List[str]:
        """Get WAF evasion recommendations based on detected WAFs"""
        with self._lock:
            if not self.detected_wafs:
                return []
        
        recommendations = []
        
        for waf in self.detected_wafs:
            if waf.waf_type == WAFType.CLOUDFLARE:
                recommendations.extend([
                    "Use --profile waf-evasion",
                    "Increase --delay to 2+ seconds",
                    "Reduce --concurrency to 1-2",
                    "Rotate User-Agent headers",
                    "Use --header-fuzz with rotated headers",
                ])
            elif waf.waf_type == WAFType.AWS_WAF:
                recommendations.extend([
                    "Add random delays between requests",
                    "Rotate source IPs if possible",
                    "Use encoded payloads (--profile waf-evasion)",
                ])
            elif waf.waf_type == WAFType.MODSECURITY:
                recommendations.extend([
                    "Use fragmented payloads",
                    "Try double encoding",
                    "Avoid common SQLi/XSS patterns in payloads",
                ])
            elif waf.waf_type == WAFType.AKAMAI:
                recommendations.extend([
                    "Add Akamai-specific headers (x-akamai-*)",
                    "Use edge-case payload variations",
                ])
            elif waf.waf_type == WAFType.IMPERVA:
                recommendations.extend([
                    "Use session persistence (cookies)",
                    "Add random delays 1-5 seconds",
                    "Fragment payloads across parameters",
                ])
        
        # General recommendations
        recommendations.extend([
            "Enable --profile waf-evasion for maximum evasion",
            "Use --mutation-level 3 for maximum payload variation",
            "Consider --proxy to rotate exit IPs",
        ])
        
        return list(set(recommendations))  # Deduplicate


class AdaptiveScanner:
    """Scanner that adapts to rate limits and WAFs"""
    
    def __init__(self, 
                 initial_concurrency: int = 5,
                 initial_delay: float = 0.5):
        self.rate_limiter = RateLimitDetector(
            max_concurrency=initial_concurrency,
            base_delay=initial_delay,
        )
        self.waf_fingerprinter = WAFFingerprinter()
        self.current_concurrency = initial_concurrency
        self.current_delay = initial_delay
        self._lock = threading.Lock()
    
    def process_response(self, status_code: int, headers: Dict[str, str],
                        body: str = "", cookies: Dict[str, str] = None,
                        response_time: float = 0) -> Dict[str, Any]:
        """Process response and return adaptive actions"""
        # Analyze rate limiting
        rate_info = self.rate_limiter.analyze_response(status_code, headers, response_time)
        
        # Analyze WAF
        waf_results = self.waf_fingerprinter.analyze(status_code, headers, body, cookies or {})
        
        # Get recommended actions
        action, reason = self.rate_limiter.get_recommended_action()
        changes = self.rate_limiter.apply_action(action)
        
        # Update current settings
        if "concurrency" in changes:
            self.current_concurrency = changes["concurrency"]
        if "delay" in changes:
            self.current_delay = changes["delay"]
        
        return {
            "rate_limit": {
                "detected": rate_info.detected,
                "info": rate_info.__dict__,
                "action": action.value,
                "reason": reason,
                "changes": changes,
            },
            "waf": {
                "detected": len(waf_results) > 0,
                "wafs": [w.__dict__ for w in waf_results],
                "evasion_recommendations": self.waf_fingerprinter.get_evasion_recommendations(),
            },
            "current_settings": {
                "concurrency": self.current_concurrency,
                "delay": self.current_delay,
            },
        }
    
    def get_current_settings(self) -> Dict[str, Any]:
        """Get current adaptive settings"""
        return {
            "concurrency": self.current_concurrency,
            "delay": self.current_delay,
            "rate_limit_stats": self.rate_limiter.get_stats(),
            "detected_wafs": [w.__dict__ for w in self.waf_fingerprinter.get_detected_wafs()],
        }
    
    def reset(self):
        """Reset adaptive settings"""
        self.rate_limiter.reset()
        with self.waf_fingerprinter._lock:
            self.waf_fingerprinter.detected_wafs.clear()
        self.current_concurrency = self.rate_limiter.max_concurrency
        self.current_delay = self.rate_limiter.base_delay


# Integration helper
def create_adaptive_scanner(concurrency: int = 5, delay: float = 0.5) -> AdaptiveScanner:
    """Create adaptive scanner with default settings"""
    return AdaptiveScanner(initial_concurrency=concurrency, initial_delay=delay)