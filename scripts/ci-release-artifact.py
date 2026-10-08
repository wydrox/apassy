#!/usr/bin/env python3
"""Copy or check the fixed macOS release artifact. Never execute its files."""

import argparse
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

try:
    import tomllib
except ModuleNotFoundError:
    raise SystemExit("ci-release-artifact: Python 3.11 or later is required")


ROOT = Path(__file__).resolve().parent.parent
BINARIES = ("apassy", "apassy-mcp", "apassy-hook", "apassy-sandbox", "apassy-browser-host")
MANIFEST = "manifest.json"
PLATFORM = {"os": "macos", "architecture": "arm64"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def valid_text(value, pattern, name):
    require(isinstance(value, str) and re.fullmatch(pattern, value) is not None,
            f"invalid {name}")
    return value


def identity(commit, run_id, run_attempt, date=None):
    result = {
        "commit": valid_text(commit, r"[0-9a-f]{40}", "commit"),
        "run_id": valid_text(run_id, r"[1-9][0-9]*", "run ID"),
        "run_attempt": valid_text(run_attempt, r"[1-9][0-9]*", "run attempt"),
    }
    if date is not None:
        valid_text(date, r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", "date")
        datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
        result["date"] = date
    return result


def package_version():
    with (ROOT / "Cargo.toml").open("rb") as stream:
        version = tomllib.load(stream)["package"]["version"]
    return valid_text(version, r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", "package version")


def check_host():
    require(platform.system() == "Darwin" and platform.machine() == "arm64",
            "the release artifact requires a macOS arm64 host")


def check_directory(directory):
    # Do not resolve first: that would hide a symlink at the supplied path.
    raw = os.fspath(directory)
    require(not any(ord(character) < 32 or ord(character) == 127 for character in raw),
            "directory contains a control character")
    path = Path(os.path.abspath(raw))
    require(not path.is_symlink() and path.is_dir(), "directory is missing or is a symlink")
    return path


def read_regular(path, max_size=None):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                f"not a single regular file: {path.name}")
        if max_size is not None:
            require(info.st_size <= max_size, f"file is too large: {path.name}")
        data = stream.read() if max_size is None else stream.read(max_size + 1)
        require(max_size is None or len(data) <= max_size, f"file is too large: {path.name}")
        return data


def binary_metadata(name, data):
    # Mach-O 64-bit, little endian, CPU_TYPE_ARM64, MH_EXECUTE.
    require(len(data) >= 32 and data[:8] == bytes.fromhex("cffaedfe0c000001")
            and data[12:16] == bytes.fromhex("02000000"),
            f"not a macOS arm64 executable: {name}")
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def check_embedded_identity(data, expected):
    for key in ("commit", "date"):
        require(expected[key].encode("ascii") in data,
                f"apassy does not contain the build {key}")


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate manifest key: {key}")
        result[key] = value
    return result


def verify(directory, commit, run_id, run_attempt, date=None, github_env=None):
    check_host()
    expected = identity(commit, run_id, run_attempt, date)
    directory = check_directory(directory)
    require({entry.name for entry in directory.iterdir()} == {*BINARIES, MANIFEST},
            "artifact must contain only the five binaries and manifest.json")
    manifest_data = read_regular(directory / MANIFEST, max_size=16384)
    manifest = json.loads(manifest_data, object_pairs_hook=no_duplicate_keys)
    require(isinstance(manifest, dict) and set(manifest) == {
        "schema", "commit", "date", "run_id", "run_attempt", "version", "platform", "files"
    }, "invalid manifest fields")
    require(type(manifest["schema"]) is int and manifest["schema"] == 1,
            "invalid manifest schema")
    identity(manifest["commit"], manifest["run_id"], manifest["run_attempt"], manifest["date"])
    for key, value in expected.items():
        require(manifest[key] == value, f"artifact {key} does not match the selected CI build")
    require(manifest["version"] == package_version(), "artifact version does not match Cargo.toml")
    require(manifest["platform"] == PLATFORM, "artifact platform does not match macOS arm64")
    require(isinstance(manifest["files"], dict) and set(manifest["files"]) == set(BINARIES),
            "manifest must name exactly the five release binaries")
    for name in BINARIES:
        metadata = manifest["files"][name]
        require(isinstance(metadata, dict) and set(metadata) == {"sha256", "size"},
                f"invalid metadata: {name}")
        valid_text(metadata["sha256"], r"[0-9a-f]{64}", f"SHA-256 for {name}")
        require(type(metadata["size"]) is int and metadata["size"] > 0,
                f"invalid size: {name}")
        data = read_regular(directory / name)
        require(metadata == binary_metadata(name, data), f"artifact hash or size mismatch: {name}")
        if name == "apassy":
            check_embedded_identity(data, manifest)
    # Validate every output value before permissions or the environment change.
    env_text = "".join(f"{key}={value}\n" for key, value in {
        "APASSY_PREBUILT_DIR": str(directory),
        "APASSY_BUILD_COMMIT": manifest["commit"],
        "APASSY_BUILD_DATE": manifest["date"],
        "APASSY_PREBUILT_RUN_ID": manifest["run_id"],
        "APASSY_PREBUILT_RUN_ATTEMPT": manifest["run_attempt"],
    }.items())
    with contextlib.ExitStack() as stack:
        env_stream = None
        if github_env is not None:
            require(not Path(github_env).is_symlink(), "GITHUB_ENV must not be a symlink")
            descriptor = os.open(github_env, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                                 | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            env_stream = stack.enter_context(os.fdopen(descriptor, "a", encoding="utf-8"))
            info = os.fstat(env_stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    "GITHUB_ENV must be a single regular file")
        binaries = []
        for name in BINARIES:
            stream = stack.enter_context(os.fdopen(os.open(directory / name, os.O_RDONLY
                                                          | os.O_NOFOLLOW | os.O_NONBLOCK), "rb"))
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    f"not a single regular file: {name}")
            require(binary_metadata(name, stream.read()) == manifest["files"][name],
                    f"artifact changed during verification: {name}")
            binaries.append(stream)
        # Artifact downloads remove execute permission. No file executes here.
        for stream in binaries:
            os.fchmod(stream.fileno(), 0o755)
        if env_stream is not None:
            env_stream.write(env_text)
    return manifest


def create(directory, commit, date, run_id, run_attempt):
    check_host()
    manifest = {"schema": 1, **identity(commit, run_id, run_attempt, date),
                "version": package_version(), "platform": PLATFORM, "files": {}}
    source = check_directory(ROOT / "target" / "release")
    contents = {name: read_regular(source / name) for name in BINARIES}
    for name, data in contents.items():
        manifest["files"][name] = binary_metadata(name, data)
    check_embedded_identity(contents["apassy"], manifest)
    path = Path(directory)
    require(not any(ord(character) < 32 or ord(character) == 127 for character in str(path)),
            "directory contains a control character")
    path.mkdir(parents=True, exist_ok=True)
    path = check_directory(path)
    require(not any(path.iterdir()), "output directory must be empty")
    for name, data in contents.items():
        with (path / name).open("xb") as stream:
            stream.write(data)
        (path / name).chmod(0o755)
    with (path / MANIFEST).open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "verify"):
        subparser = commands.add_parser(command)
        subparser.add_argument("--directory", required=True)
        subparser.add_argument("--commit", required=True)
        subparser.add_argument("--run-id", required=True)
        subparser.add_argument("--run-attempt", required=True)
        subparser.add_argument("--date", required=command == "create")
        if command == "verify":
            subparser.add_argument("--github-env")
    args = vars(parser.parse_args())
    command = args.pop("command")
    try:
        manifest = globals()[command](**args)
    except (OSError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        print(f"ci-release-artifact: {error}", file=sys.stderr)
        return 1
    print(f"ci-release-artifact: {command} passed for {manifest['commit']} (run {manifest['run_id']}/{manifest['run_attempt']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
