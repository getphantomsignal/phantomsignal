"""
NightOwl Configuration Manager — Ghost Keys & Grid Settings

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "nightowl.yaml"
_USER_CONFIG_PATH = Path.home() / ".nightowl" / "config.yaml"


class NightOwlConfig:
    """Central configuration hub for the NightOwl grid."""

    _instance: Optional["NightOwlConfig"] = None

    def __new__(cls, config_path: Optional[str] = None) -> "NightOwlConfig":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path: Optional[str] = None) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._config: Dict[str, Any] = {}
        self._load_defaults()
        self._load_file(_DEFAULT_CONFIG_PATH)
        if _USER_CONFIG_PATH.exists():
            self._load_file(_USER_CONFIG_PATH)
        if config_path:
            self._load_file(Path(config_path))
        self._apply_env_overrides()

    def _load_defaults(self) -> None:
        self._config = {
            "server": {
                "host": "127.0.0.1",
                "port": 5000,
                "debug": False,
                "secret_key": os.urandom(32).hex(),
                "workers": 4,
            },
            "database": {
                "url": "sqlite:///nightowl.db",
                "pool_size": 10,
                "echo": False,
            },
            "scraper": {
                "concurrent_requests": 16,
                "download_delay": 1.0,
                "randomize_delay": True,
                "respect_robots_txt": True,
                "user_agent_rotation": True,
                "follow_redirects": True,
                "max_depth": 3,
                "timeout": 30,
                "javascript_rendering": False,
                "proxy": None,
                "tor_enabled": False,
                "tor_port": 9050,
            },
            "port_scanner": {
                "default_ports": [
                    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                    993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
                    6379, 8080, 8443, 8888, 9200, 27017,
                ],
                "max_concurrent": 500,
                "timeout": 3,
                "service_detection": True,
            },
            "intel": {
                "enabled_apis": [],
                "rate_limit_buffer": 0.5,
                "cache_ttl": 3600,
                "auto_correlate": True,
                "shadow_scoring": True,
            },
            "export": {
                "default_format": "json",
                "output_dir": "./exports",
                "compression": False,
                "encryption": False,
                "encryption_algorithm": "AES-256-GCM",
            },
            "ghost_mode": {
                "enabled": False,
                "rotate_identity": True,
                "header_spoofing": True,
                "delay_jitter": True,
                "jitter_range": [0.5, 3.0],
            },
            "neural_profiler": {
                "enabled": False,
                "model": "local",
                "confidence_threshold": 0.75,
            },
            "notifications": {
                "desktop": True,
                "webhook_url": None,
                "slack_token": None,
            },
            "api_keys": {},
        }

    def _load_file(self, path: Path) -> None:
        if not path.exists():
            return
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        self._deep_merge(self._config, data)

    def _deep_merge(self, base: dict, override: dict) -> None:
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _apply_env_overrides(self) -> None:
        env_map = {
            "NIGHTOWL_HOST": ("server", "host"),
            "NIGHTOWL_PORT": ("server", "port"),
            "NIGHTOWL_DEBUG": ("server", "debug"),
            "NIGHTOWL_DB_URL": ("database", "url"),
            "NIGHTOWL_SECRET_KEY": ("server", "secret_key"),
            "NIGHTOWL_TOR_ENABLED": ("scraper", "tor_enabled"),
            "NIGHTOWL_PROXY": ("scraper", "proxy"),
        }
        api_key_envs = {
            "SHODAN_API_KEY": "shodan",
            "CENSYS_API_ID": "censys_id",
            "CENSYS_API_SECRET": "censys_secret",
            "HUNTER_API_KEY": "hunter",
            "HIBP_API_KEY": "hibp",
            "VIRUSTOTAL_API_KEY": "virustotal",
            "ABUSEIPDB_API_KEY": "abuseipdb",
            "GREYNOISE_API_KEY": "greynoise",
            "IPINFO_TOKEN": "ipinfo",
            "SECURITYTRAILS_API_KEY": "securitytrails",
            "URLSCAN_API_KEY": "urlscan",
            "ALIENVAULT_API_KEY": "alienvault",
            "GITHUB_TOKEN": "github",
            "TWITTER_BEARER_TOKEN": "twitter_bearer",
            "ZOOMEYE_API_KEY": "zoomeye",
            "FULLCONTACT_API_KEY": "fullcontact",
            "PIPL_API_KEY": "pipl",
            "BINARYEDGE_API_KEY": "binaryedge",
            "SPYSE_API_KEY": "spyse",
            "RISKIQ_USERNAME": "riskiq_user",
            "RISKIQ_KEY": "riskiq_key",
            "WHOISXML_API_KEY": "whoisxml",
            "GOOGLE_CSE_KEY": "google_cse",
            "GOOGLE_CSE_ID": "google_cse_id",
            "BING_SEARCH_KEY": "bing",
            "SPOKEO_API_KEY": "spokeo",
            "WHITEPAGES_API_KEY": "whitepages",
            "INTELIUS_API_KEY": "intelius",
            "CLEARBIT_API_KEY": "clearbit",
            "TELEGRAM_BOT_TOKEN": "telegram",
        }
        for env_var, (section, key) in env_map.items():
            val = os.getenv(env_var)
            if val is not None:
                if key in ("port",):
                    val = int(val)
                elif val.lower() in ("true", "false"):
                    val = val.lower() == "true"
                self._config[section][key] = val

        for env_var, api_name in api_key_envs.items():
            val = os.getenv(env_var)
            if val:
                self._config["api_keys"][api_name] = val

    def get(self, *keys: str, default: Any = None) -> Any:
        node = self._config
        for k in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(k, default)
        return node

    def set(self, *keys: str, value: Any) -> None:
        node = self._config
        for k in keys[:-1]:
            node = node.setdefault(k, {})
        node[keys[-1]] = value

    def get_api_key(self, service: str) -> Optional[str]:
        return self._config["api_keys"].get(service)

    def set_api_key(self, service: str, key: str) -> None:
        self._config["api_keys"][service] = key
        self._persist_user_config()

    def _persist_user_config(self) -> None:
        _USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_USER_CONFIG_PATH, "w") as f:
            yaml.dump({"api_keys": self._config["api_keys"]}, f)

    def as_dict(self) -> Dict[str, Any]:
        import copy
        d = copy.deepcopy(self._config)
        for k in d.get("api_keys", {}):
            if d["api_keys"][k]:
                d["api_keys"][k] = "***REDACTED***"
        return d

    @property
    def server(self) -> Dict:
        return self._config["server"]

    @property
    def scraper(self) -> Dict:
        return self._config["scraper"]

    @property
    def intel(self) -> Dict:
        return self._config["intel"]

    @property
    def export(self) -> Dict:
        return self._config["export"]

    @property
    def ghost_mode(self) -> Dict:
        return self._config["ghost_mode"]


config = NightOwlConfig()
