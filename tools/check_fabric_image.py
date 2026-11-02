"""Run inside each built production/worker image, under its default non-root user.

    docker run --rm --platform linux/arm64 --entrypoint python \\
      -v "$PWD/tools/check_fabric_image.py:/tmp/check.py:ro" IMAGE \\
      /tmp/check.py --architecture arm64

Loads the native driver with ctypes (driver enumeration alone is insufficient).
Does not access a database, obtain credentials, or imply live certification.
"""

from __future__ import annotations

import argparse
import ctypes
import glob
import json
import os
import platform
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", choices=["amd64", "arm64"], required=True)
    args = parser.parse_args()
    import msal
    import pyodbc

    expected = {"amd64": "x86_64", "arm64": "aarch64"}[args.architecture]
    if platform.machine() != expected or os.getuid() != 1000 or os.getgid() != 1000:
        raise SystemExit("Image must match expected architecture and run as uid/gid 1000")
    if "ODBC Driver 18 for SQL Server" not in pyodbc.drivers():
        raise SystemExit("Microsoft ODBC Driver 18 registration is missing")
    libraries = glob.glob("/opt/microsoft/msodbcsql18/lib64/libmsodbcsql-18*.so*")
    if len(libraries) != 1:
        raise SystemExit("Expected exactly one Microsoft ODBC Driver 18 library")
    ctypes.CDLL(libraries[0])
    print(
        json.dumps(
            {
                "architecture": args.architecture,
                "machine": platform.machine(),
                "uid": os.getuid(),
                "gid": os.getgid(),
                "msal": msal.__version__,
                "pyodbc": pyodbc.version,
                "driver_loaded": True,
                "package": subprocess.check_output(
                    ["dpkg-query", "-W", "-f=${Version}", "msodbcsql18"], text=True
                ),
                "os_release": platform.freedesktop_os_release()["PRETTY_NAME"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
