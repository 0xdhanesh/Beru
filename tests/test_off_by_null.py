"""Cross-build the off-by-null lab and test its native Linux boundaries."""

import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
from pathlib import Path


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
targets = ("linux-x86", "linux-x86_64", "linux-arm", "linux-arm64",
           "windows-x86", "windows-x86_64")
for name in ("off_by_null", "off_by_null_fixed"):
    result = subprocess.run(
        [sys.executable, "/opt/beru/compile.py", "--target", "all", f"labs/stack/{name}.c"],
        text=True, capture_output=True, timeout=180,
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    for target in targets:
        for profile in ("unprotected", "hardened"):
            filename = name + (".exe" if target.startswith("windows-") else "")
            report = Path("/out") / target / profile / (filename + ".json")
            assert json.loads(report.read_text())["verification"] == "passed"
    print(f"PASS: {name}, six targets, two verified profiles", flush=True)

native = {"aarch64": "linux-arm64", "arm64": "linux-arm64", "x86_64": "linux-x86_64"}
target = native.get(platform.machine().lower())
if target is None:
    raise AssertionError(f"Unsupported runtime test architecture: {platform.machine()}")


def execute(binary, *args, env=None):
    return subprocess.run([str(binary), *args], text=True, capture_output=True, timeout=5, env=env)


for profile in ("unprotected", "hardened"):
    for name in ("off_by_null", "off_by_null_fixed"):
        binary = Path("/out") / target / profile / name
        for args in ((), ("one", "two")):
            result = execute(binary, *args)
            assert result.returncode == 2 and "Usage:" in result.stderr
        for text in ("", "Beru", "A" * 62, "A" * 63):
            result = execute(binary, text)
            assert result.returncode == 0, result.stderr
            assert result.stdout == f"Copied: {text}\n"
        rejected_lengths = (64, 65, 66, 256, 4096) if name.endswith("_fixed") else (65, 66, 256, 4096)
        maximum = 63 if name.endswith("_fixed") else 64
        for length in rejected_lengths:
            result = execute(binary, "A" * length)
            assert result.returncode == 1 and not result.stdout
            assert result.stderr == f"Input too long: maximum is {maximum} bytes.\n"

binary = Path("/out") / target / "hardened" / "off_by_null"
result = execute(binary, "A" * 64)
assert result.returncode < 0, (result.returncode, result.stderr)
assert "buffer overflow detected" in result.stderr or "stack smashing detected" in result.stderr
print(f"PASS: {target} boundaries, usage errors, fixed rejection, hardened detection", flush=True)

# Independently demonstrate the one-byte overrun with AddressSanitizer. These
# temporary diagnostic binaries are separate from the two standard profiles.
prefix = {"linux-arm64": "aarch64-linux-gnu", "linux-x86_64": "x86_64-linux-gnu"}[target]
environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1")
with tempfile.TemporaryDirectory(dir="/out") as temporary:
    for name in ("off_by_null", "off_by_null_fixed"):
        binary = Path(temporary) / name
        subprocess.run([f"{prefix}-gcc", "-std=c11", "-O0", "-g", "-fno-omit-frame-pointer",
                        "-fsanitize=address", "-fno-pie", "-no-pie",
                        f"/src/labs/stack/{name}.c", "-o", str(binary)],
                       check=True, text=True, capture_output=True, timeout=30)
        for length in (0, 62, 63, 64, 65, 66, 256, 4096):
            result = execute(binary, "A" * length, env=environment)
            if name == "off_by_null" and length == 64:
                assert result.returncode != 0
                assert "AddressSanitizer: stack-buffer-overflow" in result.stderr
                assert "WRITE of size 65" in result.stderr
            else:
                expected = 1 if length > (63 if name.endswith("_fixed") else 64) else 0
                assert result.returncode == expected, result.stderr
                assert "AddressSanitizer" not in result.stderr
print("PASS: AddressSanitizer confirms terminator overflow only at 64 data bytes; fixed source stays in bounds", flush=True)
print("PASS: 24 verified binaries; Windows and non-native CPUs receive build verification only", flush=True)
