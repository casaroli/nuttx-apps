#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.

"""Generate an nxpkg repository index.json from built artifacts.

Scans the built package artifacts (files, or directories of them) and emits
the index.json that nxpkg consumes: one manifest per artifact with its name,
version, arch, compat, on-device artifact path, sha256 and payload type.

Per-artifact metadata comes from an optional "<artifact>.nxpkg" JSON sidecar,
for example:

    {"name": "usegreet", "version": "1.0.0", "type": "elf",
     "dependencies": ["libgreet"]}

Anything the sidecar omits is inferred: name from the file stem, version from
--default-version, arch/compat from --arch/--compat, and type from the file
name (".so" -> shared-lib, otherwise elf).
"""

import argparse
import hashlib
import json
import pathlib
import sys

SIDECAR_SUFFIX = ".nxpkg"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as infile:
        for chunk in iter(lambda: infile.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def infer_type(filename):
    return "shared-lib" if filename.endswith(".so") or ".so." in filename \
        else "elf"


def load_sidecar(artifact):
    sidecar = artifact.with_name(artifact.name + SIDECAR_SUFFIX)
    if not sidecar.exists():
        return {}

    try:
        return json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"nxpkg_export: bad sidecar {sidecar}: {exc}")


def build_entry(artifact, args):
    meta = load_sidecar(artifact)

    entry = {
        "name": meta.get("name", artifact.stem),
        "version": meta.get("version", args.default_version),
        "arch": meta.get("arch", args.arch),
        "compat": meta.get("compat", args.compat),
        "artifact": args.artifact_prefix + artifact.name,
        "sha256": sha256_file(artifact),
        "type": meta.get("type", infer_type(artifact.name)),
    }

    deps = meta.get("dependencies")
    if deps:
        entry["dependencies"] = list(deps)

    return entry


def collect_artifacts(inputs, output_name):
    files = []
    for item in inputs:
        path = pathlib.Path(item)
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if not child.is_file():
                    continue
                if child.name.endswith(SIDECAR_SUFFIX):
                    continue
                if child.name in (output_name, "index.json"):
                    continue
                files.append(child)
        elif path.is_file():
            files.append(path)
        else:
            print(f"nxpkg_export: skipping missing '{item}'", file=sys.stderr)

    return files


def main():
    parser = argparse.ArgumentParser(
        description="Generate an nxpkg repository index.json from artifacts")
    parser.add_argument("--arch", required=True,
                        help="target arch (matches CONFIG_ARCH on device)")
    parser.add_argument("--compat", required=True,
                        help="target compat (matches CONFIG_ARCH_BOARD)")
    parser.add_argument("-o", "--output", required=True,
                        help="index.json path to write")
    parser.add_argument("--artifact-prefix", default="",
                        help="prefix for the on-device artifact path")
    parser.add_argument("--default-version", default="0.0.0",
                        help="version used when a sidecar omits it")
    parser.add_argument("artifacts", nargs="+",
                        help="artifact files and/or directories to scan")
    args = parser.parse_args()

    output_name = pathlib.Path(args.output).name
    files = collect_artifacts(args.artifacts, output_name)
    if not files:
        raise SystemExit("nxpkg_export: no artifacts found")

    packages = [build_entry(artifact, args) for artifact in files]
    payload = {"packages": packages}

    pathlib.Path(args.output).write_text(
        json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")

    print(f"nxpkg_export: wrote {len(packages)} package(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
