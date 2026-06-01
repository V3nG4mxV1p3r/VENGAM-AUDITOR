"""
VENGAM — Plugin Loader
Plugin'leri dizinden otomatik keşfeder ve yükler.
"""
from __future__ import annotations
import importlib
import importlib.util
import inspect
import sys
import time
from pathlib import Path
from vengam.plugins.base import (
    VengamPlugin, ScannerPlugin, ReportPlugin,
    EnrichPlugin, HookPlugin, PluginResult,
)
from vengam.core.models import Finding, ScanResult
from vengam.utils.logger import log


class PluginLoader:
    """
    Plugin'leri dizinden yükler ve yönetir.

    Kullanım:
        loader = PluginLoader()
        loader.load_directory("vengam/plugins/community")
        results = loader.run_scanners(decompiled_dir)
    """

    def __init__(self) -> None:
        self._plugins:  dict[str, VengamPlugin] = {}
        self._scanners: list[ScannerPlugin]     = []
        self._reporters:list[ReportPlugin]      = []
        self._enrichers:list[EnrichPlugin]      = []
        self._hookers:  list[HookPlugin]        = []

    @property
    def plugin_count(self) -> int:
        return len(self._plugins)

    @property
    def scanner_count(self) -> int:
        return len(self._scanners)

    # ── Yükleme ───────────────────────────────────────────────────

    def load_directory(self, directory: str | Path) -> int:
        directory = Path(directory)
        if not directory.exists():
            return 0
        loaded = 0
        for py_file in sorted(directory.rglob("*.py")):
            if py_file.name.startswith("_"):
                continue
            if self._load_file(py_file):
                loaded += 1
        if loaded:
            log.info(f"Plugin dizini: {directory} → {loaded} plugin yüklendi")
        return loaded

    def _load_file(self, path: Path) -> bool:
        module_name = f"vengam_plugin_{path.stem}_{abs(hash(str(path)))}"
        try:
            spec   = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            found = 0
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (obj.__module__ == module_name
                        and issubclass(obj, VengamPlugin)
                        and obj is not VengamPlugin
                        and not inspect.isabstract(obj)):
                    try:
                        instance = obj()
                        self._register(instance)
                        found += 1
                        log.debug(f"Plugin yüklendi: {instance.meta.id} ({path.name})")
                    except Exception as e:
                        log.warning(f"Plugin init hatası {name}: {e}")

            return found > 0
        except Exception as e:
            log.warning(f"Plugin dosyası yüklenemedi {path}: {e}")
            return False

    def register(self, plugin: VengamPlugin) -> None:
        """Programatik olarak plugin ekle."""
        self._register(plugin)

    def _register(self, plugin: VengamPlugin) -> None:
        pid = plugin.meta.id
        if pid in self._plugins:
            log.warning(f"Plugin zaten kayıtlı, güncelleniyor: {pid}")
        self._plugins[pid] = plugin
        if isinstance(plugin, ScannerPlugin):
            self._scanners.append(plugin)
        elif isinstance(plugin, ReportPlugin):
            self._reporters.append(plugin)
        elif isinstance(plugin, EnrichPlugin):
            self._enrichers.append(plugin)
        elif isinstance(plugin, HookPlugin):
            self._hookers.append(plugin)
        try:
            plugin.on_load()
        except Exception as e:
            log.warning(f"Plugin on_load hatası {pid}: {e}")

    def unload(self, plugin_id: str) -> bool:
        plugin = self._plugins.pop(plugin_id, None)
        if not plugin:
            return False
        for lst in [self._scanners, self._reporters,
                    self._enrichers, self._hookers]:
            try:
                lst.remove(plugin)  # type: ignore
            except ValueError:
                pass
        try:
            plugin.on_unload()
        except Exception:
            pass
        log.info(f"Plugin kaldırıldı: {plugin_id}")
        return True

    # ── Çalıştırma ────────────────────────────────────────────────

    def run_scanners(
        self,
        decompiled_dir: str,
        platform:       str = "android",
        timeout_sec:    int = 120,
    ) -> list[PluginResult]:
        results = []
        for plugin in self._scanners:
            if not plugin.supports_platform(platform):
                continue
            start = time.monotonic()
            try:
                findings = plugin.scan(decompiled_dir, platform)
                results.append(PluginResult(
                    plugin_id=plugin.meta.id,
                    success=True,
                    findings=findings,
                    duration_sec=round(time.monotonic()-start, 2),
                ))
                log.info(f"Plugin {plugin.meta.id}: {len(findings)} bulgu")
            except Exception as e:
                log.error(f"Plugin {plugin.meta.id} hatası: {e}")
                results.append(PluginResult(
                    plugin_id=plugin.meta.id,
                    success=False,
                    error=str(e),
                    duration_sec=round(time.monotonic()-start, 2),
                ))
        return results

    def run_enrichers(self, findings: list[Finding]) -> list[Finding]:
        for plugin in self._enrichers:
            try:
                findings = plugin.enrich(findings)
            except Exception as e:
                log.warning(f"Enrich plugin hatası {plugin.meta.id}: {e}")
        return findings

    def run_reporters(self, result: ScanResult, output_dir: str) -> list[str]:
        paths = []
        for plugin in self._reporters:
            try:
                import os
                stem  = Path(result.apk_name).stem
                opath = os.path.join(
                    output_dir,
                    f"{stem}_{plugin.meta.id}{plugin.file_extension}"
                )
                plugin.generate(result, opath)
                paths.append(opath)
            except Exception as e:
                log.warning(f"Report plugin hatası {plugin.meta.id}: {e}")
        return paths

    def get_hook(self, finding: Finding, platform: str = "android") -> str | None:
        for plugin in self._hookers:
            try:
                if plugin.can_hook(finding):
                    hook = plugin.generate_hook(finding, platform)
                    if hook:
                        return hook
            except Exception:
                pass
        return None

    def list_plugins(self) -> list[dict]:
        return [
            {
                "id":          p.meta.id,
                "name":        p.meta.name,
                "version":     p.meta.version,
                "author":      p.meta.author,
                "type":        p.meta.plugin_type,
                "platform":    p.meta.platform,
                "description": p.meta.description,
                "tags":        p.meta.tags,
            }
            for p in self._plugins.values()
        ]


# ── Singleton ─────────────────────────────────────────────────────
_loader: PluginLoader | None = None

def get_plugin_loader() -> PluginLoader:
    global _loader
    if _loader is None:
        _loader = PluginLoader()
        plugins_dir = Path(__file__).parent / "community"
        if plugins_dir.exists():
            loaded = _loader.load_directory(plugins_dir)
            if loaded:
                log.info(f"Community plugin'ler yüklendi: {loaded}")
    return _loader
