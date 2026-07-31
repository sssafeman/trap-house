#!/usr/bin/env python3
"""Build the custom Cowrie filesystem before starting the daemon."""
import os
import subprocess
import sys

subprocess.run([sys.executable, "/opt/scripts/build_custom_pickle.py"], check=True)
os.execv(
    "/cowrie/cowrie-env/bin/twistd",
    [
        "/cowrie/cowrie-env/bin/twistd",
        "-n",
        "-" * 2 + "umask=0022",
        "-" * 2 + "pidfile=",
        "cowrie",
    ],
)
