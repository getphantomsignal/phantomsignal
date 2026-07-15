"""
PhantomSignal — Best-of-breed external tool adapters, under stealth governance.

Go-native recon tools (ProjectDiscovery's subfinder/naabu/nuclei/katana/tlsx,
masscan) are orders of magnitude faster than pure-Python at internet scale. This
module lets PhantomSignal *orchestrate* them when installed, while keeping the
OPSEC flagship intact:

* **Proxy inheritance.** A tool that supports a proxy is handed one from the same
  egress config the stealth client uses (``resolve_egress``), so its traffic is
  masked the same way. Its findings are tagged ``proxied`` when a proxy is in
  play, and honestly ``attributable`` when the tool can't proxy (e.g. masscan's
  raw sockets) or no proxy is configured.
* **Native fallback stays first-class.** ``available()`` gates every adapter on
  ``shutil.which`` — a binary-free ``pip install`` keeps working, falling back to
  the pure-Python module. External tools are always optional, never required.

Adapters subclass ``ExternalTool``, provide the command + an output parser, and
register in the scraper registry with a native fallback.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from typing import Dict, List, Optional
from urllib.parse import urlparse

from phantomsignal.core.http import resolve_egress
from phantomsignal.intel.opsec import OpsecLevel

logger = logging.getLogger("phantomsignal.scrapers.external")


def host_only(target: str) -> str:
    """Bare host from a target (strip scheme, path, port, userinfo)."""
    t = (target or "").strip().lower()
    if "://" in t:
        t = urlparse(t).netloc or t
    return t.split("/")[0].split("@")[-1].split(":")[0].lstrip(".")


def as_url(target: str) -> str:
    """A target coerced to a URL; bare hosts default to https."""
    t = (target or "").strip()
    if t.startswith(("http://", "https://")):
        return t
    return f"https://{t}"


class ExternalTool:
    """Base for a stealth-governed external CLI tool.

    Subclasses set ``BINARY``, optionally ``PROXY_FLAG`` (the tool's proxy CLI
    flag, e.g. ``-proxy``), and implement ``command()`` + ``parse()``.
    """

    BINARY: str = ""
    PROXY_FLAG: Optional[str] = None   # None → tool cannot proxy (attributable)
    TIMEOUT: float = 300.0

    def __init__(self, config):
        self.config = config

    @classmethod
    def available(cls) -> bool:
        """Is the tool installed on PATH?"""
        return bool(cls.BINARY) and shutil.which(cls.BINARY) is not None

    def _proxy(self) -> Optional[str]:
        """First real proxy from the shared egress config (tools take one)."""
        egress, _ = resolve_egress(self.config)
        for p in egress:
            if p:
                return p
        return None

    def _opsec_level(self, proxy: Optional[str]) -> OpsecLevel:
        """Honest posture: masked only if the tool actually proxied."""
        if proxy and self.PROXY_FLAG:
            return OpsecLevel.PROXIED
        return OpsecLevel.ATTRIBUTABLE

    def command(self, target: str, opts: Dict) -> List[str]:
        """The tool argv WITHOUT the proxy flag (base appends it)."""
        raise NotImplementedError

    def parse(self, stdout: str, opsec: str) -> List[Dict]:
        """Turn tool stdout into PhantomSignal result dicts. ``opsec`` is the
        posture string to stamp into each finding's ``data``."""
        raise NotImplementedError

    def _full_command(self, target: str, opts: Dict, proxy: Optional[str]) -> List[str]:
        cmd = self.command(target, opts)
        if proxy and self.PROXY_FLAG:
            cmd += [self.PROXY_FLAG, proxy]
        return cmd

    async def run(self, target: str, opts: Optional[Dict] = None) -> List[Dict]:
        """Run the tool if present; return [] if not (caller falls back)."""
        opts = opts or {}
        if not self.available():
            return []
        proxy = self._proxy()
        opsec = self._opsec_level(proxy).value
        cmd = self._full_command(target, opts, proxy)
        logger.debug("external %s: %s", self.BINARY, " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning("external %s timed out on %s", self.BINARY, target)
            return []
        except Exception as exc:
            logger.debug("external %s failed on %s: %s", self.BINARY, target, exc)
            return []
        if err and proc.returncode not in (0, None):
            logger.debug("external %s stderr: %s", self.BINARY,
                         err.decode(errors="replace")[:500])
        return self.parse(out.decode(errors="replace"), opsec)


async def run_with_fallback(external: ExternalTool, target: str, opts: Dict,
                            fallback) -> List[Dict]:
    """Run an external tool when available, else the native fallback coroutine.

    ``fallback`` is a zero-arg callable returning the native module's coroutine.
    Keeps external tools strictly optional.
    """
    if external.available():
        results = await external.run(target, opts)
        if results:
            return results
        # Tool present but produced nothing (or errored) — fall through to native
        # so a flaky binary never silently drops coverage.
    return await fallback()
