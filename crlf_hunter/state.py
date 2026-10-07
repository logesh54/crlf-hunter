"""
State persistence and resume capability for crlf-hunter
Supports saving/loading scan progress, findings, and configuration
"""

import json
import os
import pickle
import hashlib
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from pathlib import Path
from datetime import datetime, timezone
import threading
from enum import Enum


class EnumEncoder(json.JSONEncoder):
    """JSON encoder that handles enums and other non-serializable objects"""
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)


def serialize_for_json(obj: Any) -> Any:
    """Recursively convert enums and other objects to JSON-serializable values"""
    if isinstance(obj, Enum):
        return obj.value
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [serialize_for_json(v) for v in obj]
    elif hasattr(obj, '__dict__'):
        return serialize_for_json(obj.__dict__)
    return obj


@dataclass
class ScanState:
    """Complete scan state for resume capability"""
    version: str = "2.0"
    scan_id: str = ""
    created_at: str = ""
    updated_at: str = ""
    
    # Configuration
    config: Dict = field(default_factory=dict)
    
    # Targets
    targets: List[Dict] = field(default_factory=list)
    target_index: int = 0
    
    # Test cases
    total_test_cases: int = 0
    completed_test_cases: int = 0
    current_test_case_index: int = 0
    test_case_queue: List[Dict] = field(default_factory=list)  # Serialized test cases
    
    # Results
    findings: List[Dict] = field(default_factory=list)
    errors: List[Dict] = field(default_factory=list)
    
    # Statistics
    stats: Dict = field(default_factory=dict)
    
    # Sender state
    connection_pool_state: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ScanState":
        return cls(**data)


class StateManager:
    """Manages scan state persistence"""
    
    def __init__(self, state_dir: str = "state"):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._current_state: Optional[ScanState] = None
        self._auto_save_interval = 30  # seconds
        self._last_save = 0
        self._save_thread: Optional[threading.Thread] = None
        self._stop_auto_save = threading.Event()
    
    def create_state(self, scan_id: str, config: Dict, targets: List[Any], 
                     test_cases: List[Any]) -> ScanState:
        """Create new scan state"""
        state = ScanState(
            scan_id=scan_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            updated_at=datetime.now(timezone.utc).isoformat(),
            config=config,
            targets=[self._serialize_target(t) for t in targets],
            total_test_cases=len(test_cases),
            completed_test_cases=0,
            current_test_case_index=0,
            test_case_queue=[self._serialize_test_case(tc) for tc in test_cases],
            findings=[],
            errors=[],
            stats={
                "total": len(test_cases),
                "completed": 0,
                "vulnerable": 0,
                "errors": 0,
                "by_type": {},
                "by_severity": {},
            }
        )
        
        self._current_state = state
        self._save_state(state)
        return state
    
    def load_state(self, scan_id: str) -> Optional[ScanState]:
        """Load scan state from disk"""
        state_file = self.state_dir / f"{scan_id}.json"
        if not state_file.exists():
            return None
        
        try:
            with open(state_file, 'r') as f:
                data = json.load(f)
            state = ScanState.from_dict(data)
            self._current_state = state
            return state
        except Exception as e:
            print(f"Failed to load state: {e}")
            return None
    
    def list_states(self) -> List[Dict]:
        """List all saved scan states"""
        states = []
        for f in self.state_dir.glob("*.json"):
            try:
                with open(f, 'r') as fp:
                    data = json.load(fp)
                states.append({
                    "scan_id": data.get("scan_id"),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                    "progress": f"{data.get('completed_test_cases', 0)}/{data.get('total_test_cases', 0)}",
                    "findings": len(data.get("findings", [])),
                })
            except Exception:
                pass
        return sorted(states, key=lambda x: x["updated_at"], reverse=True)
    
    def update_progress(self, completed: int, current_index: int = None,
                        finding: Dict = None, error: Dict = None,
                        stats: Dict = None):
        """Update scan progress"""
        with self._lock:
            if not self._current_state:
                return
            
            state = self._current_state
            state.completed_test_cases = completed
            if current_index is not None:
                state.current_test_case_index = current_index
            state.updated_at = datetime.now(timezone.utc).isoformat()
            
            if finding:
                state.findings.append(finding)
                state.stats["vulnerable"] = state.stats.get("vulnerable", 0) + 1
                # Update by_type and by_severity
                vtype = finding.get("vulnerability_type", "unknown")
                severity = finding.get("severity", "unknown")
                state.stats["by_type"][vtype] = state.stats["by_type"].get(vtype, 0) + 1
                state.stats["by_severity"][severity] = state.stats["by_severity"].get(severity, 0) + 1
            
            if error:
                state.errors.append(error)
                state.stats["errors"] = state.stats.get("errors", 0) + 1
            
            if stats:
                state.stats.update(stats)
            
            # Auto-save periodically
            now = time.time()
            if now - self._last_save > self._auto_save_interval:
                self._save_state(state)
    
    def mark_target_complete(self, target_index: int):
        """Mark a target as fully scanned"""
        with self._lock:
            if self._current_state:
                self._current_state.target_index = target_index + 1
                self._current_state.updated_at = datetime.now(timezone.utc).isoformat()
                self._save_state(self._current_state)
    
    def get_remaining_test_cases(self) -> List[Dict]:
        """Get test cases that haven't been executed yet"""
        if not self._current_state:
            return []
        
        state = self._current_state
        return state.test_case_queue[state.current_test_case_index:]
    
    def get_completed_count(self) -> int:
        """Get number of completed test cases"""
        return self._current_state.completed_test_cases if self._current_state else 0
    
    def get_findings(self) -> List[Dict]:
        """Get all findings so far"""
        return self._current_state.findings if self._current_state else []
    
    def finalize(self):
        """Finalize and save final state"""
        if self._current_state:
            self._current_state.updated_at = datetime.now(timezone.utc).isoformat()
            self._save_state(self._current_state)
        self.stop_auto_save()
    
    def start_auto_save(self):
        """Start background auto-save thread"""
        self._stop_auto_save.clear()
        self._save_thread = threading.Thread(target=self._auto_save_loop, daemon=True)
        self._save_thread.start()
    
    def stop_auto_save(self):
        """Stop background auto-save thread"""
        self._stop_auto_save.set()
        if self._save_thread:
            self._save_thread.join(timeout=5)
    
    def _auto_save_loop(self):
        """Background auto-save loop"""
        while not self._stop_auto_save.is_set():
            time.sleep(self._auto_save_interval)
            if not self._stop_auto_save.is_set() and self._current_state:
                self._save_state(self._current_state)
    
    def _save_state(self, state: ScanState):
        """Save state to disk"""
        state.updated_at = datetime.now(timezone.utc).isoformat()
        state_file = self.state_dir / f"{state.scan_id}.json"
        try:
            with open(state_file, 'w') as f:
                json.dump(serialize_for_json(state.to_dict()), f, indent=2)
            self._last_save = time.time()
        except Exception as e:
            print(f"Failed to save state: {e}")
    
    def _serialize_target(self, target: Any) -> Dict:
        """Serialize target to dict"""
        if hasattr(target, 'to_dict'):
            return target.to_dict()
        elif hasattr(target, '__dict__'):
            return target.__dict__
        return str(target)
    
    def _serialize_test_case(self, tc: Any) -> Dict:
        """Serialize test case to dict"""
        return {
            "injection_point": {
                "type": tc.injection_point.type.value if hasattr(tc.injection_point.type, 'value') else tc.injection_point.type,
                "name": tc.injection_point.name,
                "location": tc.injection_point.location,
            },
            "payload": tc.payload,
            "raw_request": tc.raw_request.hex() if isinstance(tc.raw_request, bytes) else tc.raw_request,
            "curl_command": tc.curl_command,
            "target": self._serialize_target(tc.target) if hasattr(tc, 'target') else {},
        }
    
    def deserialize_test_case(self, data: Dict, target_map: Dict) -> Any:
        """Deserialize test case from dict (for resume)"""
        # This would need the actual classes - placeholder for now
        return data
    
    def delete_state(self, scan_id: str):
        """Delete a saved state"""
        state_file = self.state_dir / f"{scan_id}.json"
        if state_file.exists():
            state_file.unlink()
    
    def cleanup_old_states(self, max_age_days: int = 30, keep_latest: int = 10):
        """Clean up old state files"""
        states = self.list_states()
        if len(states) <= keep_latest:
            return
        
        cutoff = time.time() - (max_age_days * 86400)
        for state in states[keep_latest:]:
            try:
                updated = datetime.fromisoformat(state["updated_at"].replace('Z', '+00:00')).timestamp()
                if updated < cutoff:
                    self.delete_state(state["scan_id"])
            except Exception:
                pass


# Global state manager instance
_state_manager: Optional[StateManager] = None


def get_state_manager(state_dir: str = "state") -> StateManager:
    """Get or create global state manager"""
    global _state_manager
    if _state_manager is None:
        _state_manager = StateManager(state_dir)
    return _state_manager


def set_state_manager(manager: StateManager):
    """Set global state manager"""
    global _state_manager
    _state_manager = manager