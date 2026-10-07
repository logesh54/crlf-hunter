"""
Webhook and API notification system for real-time findings
Supports multiple webhook targets, authentication, and retry logic
"""

import json
import time
import threading
import hmac
import hashlib
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from pathlib import Path
import queue
import urllib.request
import urllib.error


class WebhookEvent(Enum):
    """Types of webhook events"""
    FINDING = "finding"
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    SCAN_ERROR = "scan_error"
    PROGRESS = "progress"
    BASELINE_COLLECTED = "baseline_collected"


@dataclass
class WebhookConfig:
    """Webhook target configuration"""
    url: str
    events: List[WebhookEvent] = field(default_factory=lambda: [WebhookEvent.FINDING])
    secret: str = ""  # HMAC secret for signature verification
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 10
    retry_count: int = 3
    retry_delay: float = 1.0
    enabled: bool = True
    name: str = ""


@dataclass
class WebhookPayload:
    """Standardized webhook payload"""
    event: WebhookEvent
    timestamp: str
    scan_id: str
    data: Dict[str, Any]
    signature: str = ""  # HMAC signature


class WebhookNotifier:
    """Manages webhook delivery with retry logic and rate limiting"""
    
    def __init__(self, configs: List[WebhookConfig] = None):
        self.configs = configs or []
        self._queue = queue.Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._stats = {
            "sent": 0,
            "failed": 0,
            "retried": 0,
        }
        self._lock = threading.Lock()
    
    def add_config(self, config: WebhookConfig):
        """Add a webhook configuration"""
        self.configs.append(config)
    
    def remove_config(self, name: str):
        """Remove a webhook configuration by name"""
        self.configs = [c for c in self.configs if c.name != name]
    
    def notify(self, event: WebhookEvent, scan_id: str, data: Dict[str, Any]):
        """Queue a notification for delivery"""
        for config in self.configs:
            if config.enabled and event in config.events:
                payload = WebhookPayload(
                    event=event,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    scan_id=scan_id,
                    data=data,
                )
                # Generate signature if secret provided
                if config.secret:
                    payload.signature = self._generate_signature(config.secret, payload)
                
                self._queue.put((config, payload))
    
    def _generate_signature(self, secret: str, payload: WebhookPayload) -> str:
        """Generate HMAC-SHA256 signature"""
        message = json.dumps({
            "event": payload.event.value,
            "timestamp": payload.timestamp,
            "scan_id": payload.scan_id,
            "data": payload.data,
        }, sort_keys=True)
        return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    
    def start(self):
        """Start the delivery worker thread"""
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._delivery_loop, daemon=True)
        self._worker_thread.start()
    
    def stop(self):
        """Stop the delivery worker thread"""
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
    
    def _delivery_loop(self):
        """Main delivery loop"""
        while not self._stop_event.is_set():
            try:
                config, payload = self._queue.get(timeout=1)
                self._deliver(config, payload)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Webhook delivery error: {e}")
    
    def _deliver(self, config: WebhookConfig, payload: WebhookPayload):
        """Deliver a single webhook with retries"""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "crlf-hunter-webhook/2.0",
            **config.headers,
        }
        
        if config.secret:
            headers["X-Signature"] = payload.signature
        
        body = json.dumps({
            "event": payload.event.value,
            "timestamp": payload.timestamp,
            "scan_id": payload.scan_id,
            "data": payload.data,
        }).encode()
        
        for attempt in range(config.retry_count + 1):
            try:
                req = urllib.request.Request(
                    config.url,
                    data=body,
                    headers=headers,
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=config.timeout) as resp:
                    if 200 <= resp.status < 300:
                        with self._lock:
                            self._stats["sent"] += 1
                        return
                    else:
                        raise urllib.error.HTTPError(config.url, resp.status, 
                            f"HTTP {resp.status}", resp.headers, None)
            except Exception as e:
                if attempt < config.retry_count:
                    with self._lock:
                        self._stats["retried"] += 1
                    time.sleep(config.retry_delay * (attempt + 1))
                else:
                    with self._lock:
                        self._stats["failed"] += 1
                    print(f"Webhook delivery failed for {config.name}: {e}")
    
    def get_stats(self) -> Dict[str, int]:
        """Get delivery statistics"""
        with self._lock:
            return self._stats.copy()
    
    def wait_for_queue(self, timeout: float = 30):
        """Wait for queue to be processed"""
        self._queue.join()


class APINotifier:
    """REST API notifier for integration with SIEM/SOAR platforms"""
    
    def __init__(self, base_url: str, api_key: str = "", timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
    
    def send_finding(self, finding: Dict[str, Any]) -> bool:
        """Send a finding to the API"""
        url = f"{self.base_url}/api/v1/findings"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "crlf-hunter-api/2.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(finding).encode(),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            print(f"API notification failed: {e}")
            return False
    
    def send_batch(self, findings: List[Dict[str, Any]]) -> int:
        """Send multiple findings in batch"""
        url = f"{self.base_url}/api/v1/findings/batch"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "crlf-hunter-api/2.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps({"findings": findings}).encode(),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if 200 <= resp.status < 300:
                    return len(findings)
        except Exception as e:
            print(f"Batch API notification failed: {e}")
        return 0


class FindingFormatter:
    """Format findings for different notification targets"""
    
    @staticmethod
    def for_webhook(finding: Any) -> Dict[str, Any]:
        """Format finding for webhook delivery"""
        return {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "type": finding.vulnerability_type,
            "target": finding.target_url,
            "injection_point": finding.injection_point,
            "evidence": finding.evidence,
            "confidence": finding.confidence,
            "timestamp": finding.timestamp,
            "tags": finding.tags,
            "cve_references": finding.cve_references,
        }
    
    @staticmethod
    def for_slack(finding: Any) -> Dict[str, Any]:
        """Format finding for Slack webhook"""
        color_map = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#20c997",
            "info": "#17a2b8",
        }
        color = color_map.get(finding.severity.value, "#6c757d")
        
        return {
            "attachments": [{
                "color": color,
                "title": f"🔍 {finding.title}",
                "fields": [
                    {"title": "Target", "value": finding.target_url, "short": True},
                    {"title": "Type", "value": finding.vulnerability_type, "short": True},
                    {"title": "Severity", "value": finding.severity.value.upper(), "short": True},
                    {"title": "Confidence", "value": finding.confidence, "short": True},
                    {"title": "Injection Point", "value": finding.injection_point, "short": False},
                    {"title": "Evidence", "value": finding.evidence[:200], "short": False},
                ],
                "footer": "crlf-hunter",
                "ts": int(datetime.fromisoformat(finding.timestamp.replace('Z', '+00:00')).timestamp()),
            }]
        }
    
    @staticmethod
    def for_discord(finding: Any) -> Dict[str, Any]:
        """Format finding for Discord webhook"""
        color_map = {
            "critical": 0xdc3545,
            "high": 0xfd7e14,
            "medium": 0xffc107,
            "low": 0x20c997,
            "info": 0x17a2b8,
        }
        color = color_map.get(finding.severity.value, 0x6c757d)
        
        return {
            "embeds": [{
                "title": f"🔍 {finding.title}",
                "description": f"CRLF Injection vulnerability detected",
                "color": color,
                "fields": [
                    {"name": "Target", "value": finding.target_url, "inline": True},
                    {"name": "Type", "value": finding.vulnerability_type, "inline": True},
                    {"name": "Severity", "value": finding.severity.value.upper(), "inline": True},
                    {"name": "Injection Point", "value": finding.injection_point, "inline": False},
                    {"name": "Evidence", "value": f"```{finding.evidence[:500]}```", "inline": False},
                ],
                "footer": {"text": "crlf-hunter"},
                "timestamp": finding.timestamp,
            }]
        }
    
    @staticmethod
    def for_teams(finding: Any) -> Dict[str, Any]:
        """Format finding for Microsoft Teams webhook"""
        color_map = {
            "critical": "FF0000",
            "high": "FF8C00",
            "medium": "FFD700",
            "low": "32CD32",
            "info": "00BFFF",
        }
        color = color_map.get(finding.severity.value, "808080")
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"CRLF Hunter: {finding.title}",
            "sections": [{
                "activityTitle": f"🔍 {finding.title}",
                "activitySubtitle": "CRLF Injection vulnerability detected",
                "facts": [
                    {"name": "Target", "value": finding.target_url},
                    {"name": "Type", "value": finding.vulnerability_type},
                    {"name": "Severity", "value": finding.severity.value.upper()},
                    {"name": "Confidence", "value": finding.confidence},
                    {"name": "Injection Point", "value": finding.injection_point},
                ],
                "markdown": True,
            }],
        }


# Convenience functions
def create_webhook_notifier(webhooks: List[Dict[str, Any]]) -> WebhookNotifier:
    """Create WebhookNotifier from config list"""
    notifier = WebhookNotifier()
    for w in webhooks:
        config = WebhookConfig(
            url=w["url"],
            events=[WebhookEvent(e) for e in w.get("events", ["finding"])],
            secret=w.get("secret", ""),
            headers=w.get("headers", {}),
            timeout=w.get("timeout", 10),
            retry_count=w.get("retry_count", 3),
            retry_delay=w.get("retry_delay", 1.0),
            enabled=w.get("enabled", True),
            name=w.get("name", w["url"][:50]),
        )
        notifier.add_config(config)
    return notifier


def create_slack_webhook(url: str, events: List[str] = None) -> WebhookConfig:
    """Create Slack-compatible webhook config"""
    return WebhookConfig(
        url=url,
        events=[WebhookEvent(e) for e in (events or ["finding"])],
        headers={"Content-Type": "application/json"},
        name="Slack",
    )


def create_discord_webhook(url: str, events: List[str] = None) -> WebhookConfig:
    """Create Discord-compatible webhook config"""
    return WebhookConfig(
        url=url,
        events=[WebhookEvent(e) for e in (events or ["finding"])],
        headers={"Content-Type": "application/json"},
        name="Discord",
    )


def create_teams_webhook(url: str, events: List[str] = None) -> WebhookConfig:
    """Create Microsoft Teams-compatible webhook config"""
    return WebhookConfig(
        url=url,
        events=[WebhookEvent(e) for e in (events or ["finding"])],
        headers={"Content-Type": "application/json"},
        name="Teams",
    )