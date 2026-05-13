#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import pathlib
import sys


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as infile:
        while True:
            chunk = infile.read(4096)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def write_index(path: pathlib.Path, arch: str, compat: str,
                artifact: str, digest: str) -> None:
    payload = {
        "packages": [
            {
                "name": "hello",
                "version": "1.0.0",
                "arch": arch,
                "compat": compat,
                "artifact": artifact,
                "sha256": digest,
                "type": "elf",
            }
        ]
    }

    path.write_text(json.dumps(payload, separators=(",", ":")) + "\n",
                    encoding="utf-8")


def write_script(path: pathlib.Path) -> None:
    script = "\n".join(
        [
            "mount -t tmpfs /etc",
            "mount -t tmpfs /var",
            "mkdir /etc/nxpkg",
            "cp /mnt/elf/romfs/index.json /etc/nxpkg/index.json",
            "nxpkg install hello",
            "nxpkg list",
            "",
        ]
    )
    path.write_text(script, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: mk_pkg_fixture.py <hello-bin> <index-json> <pkgtest-nsh> "
            "<arch> <compat>",
            file=sys.stderr,
        )
        return 1

    hello = pathlib.Path(sys.argv[1])
    index = pathlib.Path(sys.argv[2])
    script = pathlib.Path(sys.argv[3])
    arch = sys.argv[4]
    compat = sys.argv[5]
    artifact = "/mnt/elf/romfs/hello"

    digest = sha256_file(hello)
    write_index(index, arch, compat, artifact, digest)
    write_script(script)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
