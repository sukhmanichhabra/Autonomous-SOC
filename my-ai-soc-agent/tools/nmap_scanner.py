"""
Nmap Scanner Tools  (compatibility shim)
=========================================
All scanning functionality has been moved to :mod:`tools.recon_toolkit`.
This module re-exports the original Nmap functions so that existing
imports (``from tools.nmap_scanner import …``) continue to work.
"""

from tools.recon_toolkit import (          # noqa: F401  — re-export
    nmap_scan,
    quick_scan,
    vulnerability_scan,
    format_scan_results,
    run_quick_scan,
)
