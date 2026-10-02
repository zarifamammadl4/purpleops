"""
WinRM remote execution client for PurpleOps.
Lets purpleops.py execute ATT&CK test commands directly on the Windows endpoint,
instead of relying on a human to paste them manually.
"""

import os
import winrm

WINDOWS_HOST = os.environ.get("WINDOWS_HOST", "192.168.56.103")
WINDOWS_USER = os.environ.get("WINDOWS_USER", "Administrator")
WINDOWS_PASSWORD = os.environ.get("WINDOWS_PASSWORD")


def execute_remote(command, timeout=30):
    """Run a PowerShell command on the Windows endpoint over WinRM.
    Returns (status_code, stdout, stderr)."""
    if not WINDOWS_PASSWORD:
        raise RuntimeError(
            "WINDOWS_PASSWORD is not set. Create a .env file (see .env.example) "
            "and load it, e.g.: export $(grep -v '^#' .env | xargs)"
        )
    session = winrm.Session(
        WINDOWS_HOST,
        auth=(WINDOWS_USER, WINDOWS_PASSWORD),
        transport="basic",
        read_timeout_sec=timeout + 5,
        operation_timeout_sec=timeout,
    )
    result = session.run_ps(command)
    return result.status_code, result.std_out.decode(errors="replace"), result.std_err.decode(errors="replace")


if __name__ == "__main__":
    code, out, err = execute_remote("whoami; Get-Date")
    print("STATUS:", code)
    print("OUT:", out)
    if err:
        print("ERR:", err)
