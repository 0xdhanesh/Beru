"""Build every target; exercise boundary cases on the container's native Linux CPU."""

import json
import platform
import resource
import subprocess
import sys
from pathlib import Path


# Expected hardened aborts must not leave core files in the output directory.
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
targets = ("linux-x86", "linux-x86_64", "linux-arm", "linux-arm64",
           "windows-x86", "windows-x86_64")
for name in ("classic_overflow", "classic_overflow_fixed"):
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


def execute(name, profile, *args):
    binary = Path("/out") / target / profile / name
    return subprocess.run([str(binary), *args], text=True, capture_output=True, timeout=5)


for profile in ("unprotected", "hardened"):
    for name in ("classic_overflow", "classic_overflow_fixed"):
        for args in ((), ("one", "two")):
            result = execute(name, profile, *args)
            assert result.returncode == 2 and "Usage:" in result.stderr
        for text in ("", "Beru", "A" * 63):
            result = execute(name, profile, text)
            assert result.returncode == 0, result.stderr
            assert result.stdout == f"Copied: {text}\n"
        if name.endswith("_fixed"):
            for text in ("A" * 64, "A" * 65, "A" * 256, "A" * 4096):
                result = execute(name, profile, text)
                assert result.returncode == 1 and not result.stdout
                assert result.stderr == "Input too long: maximum is 63 bytes.\n"

# Fortify must stop the first overflowing length, including the NUL-only overrun.
for length in (64, 65, 256):
    result = execute("classic_overflow", "hardened", "A" * length)
    assert result.returncode < 0, (length, result.returncode, result.stderr)
    assert "buffer overflow detected" in result.stderr or "stack smashing detected" in result.stderr

# Confirm that the unprotected binary still calls the unchecked copy routine.
prefix = {"linux-arm64": "aarch64-linux-gnu", "linux-x86_64": "x86_64-linux-gnu"}[target]
binary = Path("/out") / target / "unprotected" / "classic_overflow"
symbols = subprocess.run([f"{prefix}-objdump", "-T", str(binary)],
                         check=True, text=True, capture_output=True).stdout
assert "strcpy" in symbols and "__strcpy_chk" not in symbols
print(f"PASS: {target} runtime boundaries, usage errors, fixed rejection, hardened aborts", flush=True)
print("PASS: 24 verified binaries; Windows and non-native CPUs receive build verification only", flush=True)
