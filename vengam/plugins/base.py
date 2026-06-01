"""
VENGAM — Plugin System Base
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from vengam.core.models import Finding, ScanResult


@dataclass
class PluginMeta:
    id:          str
    name:        str
    version:     str
    author:      str
    description: str
    plugin_type: str
    platform:    str = "both"
    tags:        list[str] = field(default_factory=list)
    requires:    list[str] = field(default_factory=list)


class VengamPlugin(ABC):
    @property
    @abstractmethod
    def meta(self) -> PluginMeta: ...
    def on_load(self) -> None: pass
    def on_unload(self) -> None: pass


class ScannerPlugin(VengamPlugin):
    @abstractmethod
    def scan(self, decompiled_dir: str, platform: str = "android") -> list[Finding]: ...
    def supports_platform(self, platform: str) -> bool:
        return self.meta.platform in (platform, "both")


class ReportPlugin(VengamPlugin):
    @abstractmethod
    def generate(self, result: ScanResult, output_path: str) -> None: ...
    @property
    def file_extension(self) -> str: return ".txt"


class EnrichPlugin(VengamPlugin):
    @abstractmethod
    def enrich(self, findings: list[Finding]) -> list[Finding]: ...


class HookPlugin(VengamPlugin):
    @abstractmethod
    def generate_hook(self, finding: Finding, platform: str = "android") -> str | None: ...
    @abstractmethod
    def can_hook(self, finding: Finding) -> bool: ...


@dataclass
class PluginResult:
    plugin_id:    str
    success:      bool
    findings:     list[Finding] = field(default_factory=list)
    error:        str | None    = None
    duration_sec: float         = 0.0
    metadata:     dict          = field(default_factory=dict)
