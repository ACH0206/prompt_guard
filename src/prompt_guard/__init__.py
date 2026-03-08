"""
Prompt Guard - Lightweight prompt injection detection for LLM applications.

Usage:
    from prompt_guard import scan_input, scan_output

    # Check user input before sending to LLM
    result = scan_input(text, allowed_dirs=["/safe/dir"])
    if result.blocked:
        print(result.findings)

    # Check LLM output before returning to user
    output = scan_output(response, canary="MY_CANARY")
    safe_text = output.redacted_text
"""

from .input_filter import scan_input, ScanResult
from .output_filter import scan_output, OutputScanResult
from .audit import AuditLogger
from .user_manager import UserManager

__all__ = [
    "scan_input",
    "scan_output",
    "ScanResult",
    "OutputScanResult",
    "AuditLogger",
    "UserManager",
]
