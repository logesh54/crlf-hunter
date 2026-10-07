"""
Configuration file support (YAML/JSON)
Allows saving and loading scan configurations
"""

import os
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, fields, field
from pathlib import Path
from enum import Enum


class ConfigFormat(Enum):
    """Configuration file formats"""
    YAML = "yaml"
    JSON = "json"


@dataclass
class ScanConfig:
    """Complete scan configuration"""
    # Target settings
    targets: List[str] = field(default_factory=list)
    target_file: str = ""
    
    # Scan profile
    profile: str = "standard"
    mutation_level: int = 1
    max_payloads_per_point: int = 100
    
    # Injection options
    header_fuzz: bool = True
    body_fuzz: bool = False
    cookie_fuzz: bool = True
    path_fuzz: bool = False
    method_fuzz: bool = False
    params: str = ""
    body_params: str = ""
    custom_header_list: str = ""
    method: str = "GET"
    
    # Authentication
    auth_type: str = "none"
    auth_user: str = ""
    auth_pass: str = ""
    auth_token: str = ""
    login_url: str = ""
    login_method: str = "POST"
    
    # Proxy
    proxy: str = ""
    proxy_user: str = ""
    proxy_pass: str = ""
    proxy_type: str = "http"
    
    # TLS
    tls_verify: bool = False
    
    # Custom headers/cookies
    custom_headers: str = ""
    cookies: str = ""
    
    # Timing
    delay: float = 0.5
    timeout: int = 10
    concurrency: int = 5
    
    # Analysis
    differential: bool = True
    no_timing: bool = False
    follow_redirects: bool = False
    max_redirects: int = 5
    max_connections: int = 10
    
    # Output
    output: str = ""
    output_dir: str = "reports"
    format: str = "json,html"
    verbose: bool = False
    quiet: bool = False
    
    # Scope
    scope_domain: str = ""
    deduplicate: bool = True
    
    # Webhooks
    webhook_url: List[str] = field(default_factory=list)
    webhook_events: str = "finding"
    webhook_secret: str = ""
    webhook_timeout: int = 10
    webhook_retry: int = 3
    slack_webhook: str = ""
    discord_webhook: str = ""
    teams_webhook: str = ""
    api_url: str = ""
    api_key: str = ""
    
    # Resume/State
    resume: str = ""
    state_dir: str = "state"
    no_save_state: bool = False
    list_states: bool = False
    cleanup_states: bool = False
    
    # Safety
    confirm: bool = False
    
    # Severity/tags filtering
    severity: str = ""
    tags: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ScanConfig":
        """Create from dictionary"""
        # Filter only valid fields
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)
    
    def to_yaml(self) -> str:
        """Convert to YAML string"""
        try:
            import yaml
            return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)
        except ImportError:
            raise ImportError("PyYAML required for YAML support: pip install pyyaml")
    
    @classmethod
    def from_yaml(cls, yaml_str: str) -> "ScanConfig":
        """Create from YAML string"""
        try:
            import yaml
            data = yaml.safe_load(yaml_str)
            return cls.from_dict(data)
        except ImportError:
            raise ImportError("PyYAML required for YAML support: pip install pyyaml")
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> "ScanConfig":
        """Create from JSON string"""
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def save(self, filepath: str):
        """Save to file (auto-detect format)"""
        path = Path(filepath)
        if path.suffix.lower() in (".yaml", ".yml"):
            path.write_text(self.to_yaml())
        elif path.suffix.lower() == ".json":
            path.write_text(self.to_json())
        else:
            # Default to YAML
            path.write_text(self.to_yaml())
    
    @classmethod
    def load(cls, filepath: str) -> "ScanConfig":
        """Load from file (auto-detect format)"""
        path = Path(filepath)
        content = path.read_text()
        if path.suffix.lower() in (".yaml", ".yml"):
            return cls.from_yaml(content)
        elif path.suffix.lower() == ".json":
            return cls.from_json(content)
        else:
            # Try YAML first, then JSON
            try:
                return cls.from_yaml(content)
            except Exception:
                return cls.from_json(content)


class ConfigManager:
    """Manages configuration files and profiles"""
    
    def __init__(self, config_dir: str = "config"):
        # Use XDG config directory or project directory
        if not os.path.isabs(config_dir):
            # Try XDG config directory first
            xdg_config = os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))
            config_dir = os.path.join(xdg_config, 'crlf-hunter', config_dir)
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def save_config(self, name: str, config: ScanConfig) -> str:
        """Save named configuration"""
        filepath = self.config_dir / f"{name}.yaml"
        config.save(str(filepath))
        return str(filepath)
    
    def load_config(self, name: str) -> Optional[ScanConfig]:
        """Load named configuration"""
        for ext in [".yaml", ".yml", ".json"]:
            filepath = self.config_dir / f"{name}{ext}"
            if filepath.exists():
                return ScanConfig.load(str(filepath))
        return None
    
    def list_configs(self) -> List[str]:
        """List available configurations"""
        configs = []
        for ext in [".yaml", ".yml", ".json"]:
            for f in self.config_dir.glob(f"*{ext}"):
                configs.append(f.stem)
        return sorted(set(configs))
    
    def delete_config(self, name: str) -> bool:
        """Delete configuration"""
        for ext in [".yaml", ".yml", ".json"]:
            filepath = self.config_dir / f"{name}{ext}"
            if filepath.exists():
                filepath.unlink()
                return True
        return False
    
    def create_default(self) -> ScanConfig:
        """Create default configuration"""
        return ScanConfig()


def create_config_from_args(args) -> ScanConfig:
    """Create ScanConfig from argparse namespace"""
    config = ScanConfig()
    
    # Map args to config fields
    for field_name in [f.name for f in fields(ScanConfig)]:
        if hasattr(args, field_name):
            value = getattr(args, field_name)
            if value is not None:
                setattr(config, field_name, value)
    
    return config


def apply_config_to_args(config: ScanConfig, args) -> Any:
    """Apply configuration to argparse namespace"""
    for field_name in [f.name for f in fields(ScanConfig)]:
        if hasattr(config, field_name):
            value = getattr(config, field_name)
            if value is not None and value != "" and value != [] and value is not False:
                # Only override if not explicitly set via CLI
                # This is a simple heuristic - in practice you'd want better logic
                current = getattr(args, field_name, None)
                if current is None or current == "" or current == [] or current is False:
                    setattr(args, field_name, value)
    return args


# Default configurations
DEFAULT_CONFIGS = {
    "quick": ScanConfig(
        profile="quick",
        mutation_level=0,
        max_payloads_per_point=20,
        concurrency=10,
        delay=0.2,
        format="json",
    ),
    "standard": ScanConfig(
        profile="standard",
        mutation_level=1,
        max_payloads_per_point=100,
        concurrency=5,
        delay=0.5,
        format="json,html",
    ),
    "deep": ScanConfig(
        profile="deep",
        mutation_level=2,
        max_payloads_per_point=500,
        concurrency=3,
        delay=1.0,
        format="json,html,sarif",
        header_fuzz=True,
        body_fuzz=True,
        cookie_fuzz=True,
        path_fuzz=True,
    ),
    "waf-evasion": ScanConfig(
        profile="waf-evasion",
        mutation_level=3,
        max_payloads_per_point=300,
        concurrency=2,
        delay=2.0,
        format="json,html,sarif",
        header_fuzz=True,
        body_fuzz=True,
        cookie_fuzz=True,
        path_fuzz=True,
    ),
    "ci": ScanConfig(
        profile="standard",
        mutation_level=1,
        max_payloads_per_point=100,
        concurrency=5,
        delay=0.5,
        format="sarif,junit",
        output_dir="reports",
        quiet=True,
        no_save_state=True,
    ),
}


def get_default_config(name: str) -> Optional[ScanConfig]:
    """Get a default configuration by name"""
    return DEFAULT_CONFIGS.get(name)


def merge_configs(base: ScanConfig, override: ScanConfig) -> ScanConfig:
    """Merge two configurations, override takes precedence"""
    base_dict = base.to_dict()
    override_dict = override.to_dict()
    
    # Only override non-None/empty values
    for k, v in override_dict.items():
        if v is not None and v != "" and v != [] and v is not False:
            base_dict[k] = v
    
    return ScanConfig.from_dict(base_dict)