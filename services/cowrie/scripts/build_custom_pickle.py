#!/usr/bin/env python3
"""Build a custom fs.pickle for cowrie with /home/admin/ decoy files.

Injects /home/admin/.env and /home/admin/README.md into the bundled
fs.pickle so attackers who SSH into cowrie and explore the filesystem
find planted decoy credentials.

Usage (inside the cowrie container):
    python3 /opt/scripts/build_custom_pickle.py

Or from the host:
    docker exec trap-cowrie python3 /opt/scripts/build_custom_pickle.py

The script reads the bundled fs.pickle, injects the admin home directory
with file contents from the honeyfs bind mount, and writes the result
to /cowrie/cowrie-git/var/fs.custom.pickle.

The cowrie.cfg points [shell] filesystem to this custom pickle.
"""

import os
import pickle
import sys

# Entry tuple field indices (from cowrie.shell.honeyfs)
A_NAME = 0
A_TYPE = 1
A_CONTENTS = 7
A_TARGET = 8

T_LINK = 0
T_DIR = 1
T_FILE = 2

# Paths
BUNDLED_PICKLE = "/cowrie/cowrie-git/src/cowrie/data/fs.pickle"
CUSTOM_PICKLE = "/cowrie/cowrie-git/var/fs.custom.pickle"
HONEYFS_HOME = "/cowrie/cowrie-git/honeyfs/home/admin"

# Files to inject into /home/admin/
DECOY_FILES = [".env", "README.md"]


def find(tree, path):
    """Walk the pickle tree to find the entry at path."""
    parts = [p for p in path.split("/") if p]
    node = tree
    for p in parts:
        kids = node[A_CONTENTS] if isinstance(node[A_CONTENTS], list) else []
        m = next((c for c in kids if c[A_NAME] == p), None)
        if m is None:
            return None
        node = m
    return node


def main():
    if not os.path.exists(BUNDLED_PICKLE):
        print(f"ERROR: Bundled pickle not found at {BUNDLED_PICKLE}")
        sys.exit(1)

    with open(BUNDLED_PICKLE, "rb") as f:
        tree = pickle.load(f)

    home = find(tree, "/home")
    if home is None:
        print("ERROR: /home not found in pickle tree")
        sys.exit(1)

    # Remove existing admin entry if present (for idempotency)
    if isinstance(home[A_CONTENTS], list):
        home[A_CONTENTS] = [c for c in home[A_CONTENTS] if c[A_NAME] != "admin"]

    # Build admin directory with decoy files
    children = []
    for filename in DECOY_FILES:
        filepath = os.path.join(HONEYFS_HOME, filename)
        if os.path.exists(filepath):
            content = open(filepath, "rb").read()
        else:
            print(f"WARNING: {filepath} not found, skipping")
            continue
        entry = [filename, T_FILE, 0o644, 1000, 1000, 0, 0, content, None]
        children.append(entry)
        print(f"  Injected: /home/admin/{filename} ({len(content)} bytes)")

    admin_entry = ["admin", T_DIR, 0o755, 1000, 1000, 0, 0, children, None]
    home[A_CONTENTS].append(admin_entry)

    # Ensure var directory exists
    os.makedirs(os.path.dirname(CUSTOM_PICKLE), exist_ok=True)

    with open(CUSTOM_PICKLE, "wb") as f:
        pickle.dump(tree, f)

    print(f"Custom pickle written to {CUSTOM_PICKLE} ({os.path.getsize(CUSTOM_PICKLE)} bytes)")

    # Verify
    with open(CUSTOM_PICKLE, "rb") as f:
        tree2 = pickle.load(f)
    admin2 = find(tree2, "/home/admin")
    if admin2 and isinstance(admin2[A_CONTENTS], list):
        print("Verified /home/admin contents:", [(c[A_NAME], c[A_TYPE]) for c in admin2[A_CONTENTS]])
    else:
        print("ERROR: Verification failed")
        sys.exit(1)


if __name__ == "__main__":
    main()