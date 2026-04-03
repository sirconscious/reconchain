"""
VSec — AI-Powered Penetration Testing Framework

A modular, extensible reconnaissance framework built with LangChain/LangGraph.

Usage:
    from vsec import TOOLS, agent, settings
    from vsec.tools import discover_tools, list_tools
"""
__version__ = "0.1.0"

import vsec.tools
import vsec.config

settings = vsec.config.settings

__all__ = [
    "tools",
    "config",
    "settings",
]
