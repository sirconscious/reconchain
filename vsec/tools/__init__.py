"""
VSec Tools — Plugin Discovery System

Tools are automatically discovered from:
- vsec/tools/defaults/  → Built-in tools (shipped with VSec)
- vsec/tools/custom/    → User-added tools (gitignored)

To add a new tool:
1. Create a .py file in vsec/tools/custom/
2. Define functions decorated with @tool
3. Restart VSec — tool is auto-loaded
"""
import importlib
import pkgutil
import sys
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from vsec.config import settings


# Store discovered tools (module-level globals)
TOOLS: list[Any] = []
TOOL_REGISTRY: dict[str, Any] = {}


def _discover_tools_in_package(package_path: Path) -> None:
    """Discover tools in a package directory."""
    if not package_path.exists():
        return
    
    for module_info in pkgutil.iter_modules([str(package_path)]):
        if module_info.name.startswith("_"):
            continue
        
        try:
            module = importlib.import_module(
                f"vsec.tools.defaults.{module_info.name}"
            )
            
            for name in dir(module):
                if name.startswith("_"):
                    continue
                
                obj = getattr(module, name)
                
                if hasattr(obj, "name") and hasattr(obj, "invoke"):
                    if obj.name not in TOOL_REGISTRY:
                        TOOL_REGISTRY[obj.name] = obj
        except Exception as e:
            print(f"  ⚠ Failed to load {module_info.name}: {e}")


def _discover_custom_tools() -> None:
    """Discover custom tools in the custom/ directory."""
    custom_path = Path(__file__).parent / "custom"
    
    if not custom_path.exists():
        return
    
    for py_file in custom_path.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        
        module_name = py_file.stem
        
        if module_name in sys.modules:
            module = sys.modules[module_name]
            importlib.reload(module)
        else:
            spec = importlib.util.spec_from_file_location(
                f"vsec.tools.custom.{module_name}", py_file
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[f"vsec.tools.custom.{module_name}"] = module
                spec.loader.exec_module(module)
        
        for name in dir(module):
            if name.startswith("_"):
                continue
            
            obj = getattr(module, name)
            
            if callable(obj) and hasattr(obj, "name"):
                if obj.name not in TOOL_REGISTRY:
                    TOOL_REGISTRY[obj.name] = obj


def _load_cve_if_enabled() -> None:
    """Load CVE dataset if CVE tool is enabled."""
    if not settings.cve_enabled:
        return
    
    try:
        from vsec.tools.defaults.cve import _load_cve_dataset
        _load_cve_dataset()
    except ImportError:
        pass


def discover_tools() -> list[Any]:
    """Discover and load all available tools."""
    global TOOLS, TOOL_REGISTRY
    
    TOOL_REGISTRY.clear()
    TOOLS.clear()
    
    defaults_path = Path(__file__).parent / "defaults"
    _discover_tools_in_package(defaults_path)
    
    _discover_custom_tools()
    
    enabled_tools = [
        "get_dnsdumpster", "get_whois",
        "get_http_headers", "get_robots_txt", "get_nmap_scan", "check_common_paths",
        "run_gobuster_dirs", "run_gobuster_subs", "detect_technologies",
        "retrieve_cve_info",
    ]
    
    if settings.shell_enabled:
        enabled_tools.append("shell")
    
    for tool_name in enabled_tools:
        if tool_name in TOOL_REGISTRY:
            TOOLS.append(TOOL_REGISTRY[tool_name])
    
    return TOOLS


def list_tools() -> list[str]:
    """Return list of available tool names."""
    return list(TOOL_REGISTRY.keys())


def get_tool(name: str) -> Any | None:
    """Get a specific tool by name."""
    return TOOL_REGISTRY.get(name)


# Auto-discover tools on import
discover_tools()
_load_cve_if_enabled()


__all__ = [
    "TOOLS",
    "tool",
    "discover_tools",
    "list_tools",
    "get_tool",
]
