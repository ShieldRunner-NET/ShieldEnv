"""ShieldEnv: fast secret scanning for repositories and CI pipelines."""

from .scanner import Finding, ScanResult, scan_path

__all__ = ["Finding", "ScanResult", "scan_path"]
__version__ = "1.0.0"
