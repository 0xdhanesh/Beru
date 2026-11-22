"""Cross-build the global overflow lab and check native Linux boundaries."""

import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
from pathlib import Path


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
names = ("buffer_overflow", "buffer_overflow_fixed")
targets = ("linux-x86", "linux-x86_64", "linux-arm", "linux-arm64",
           "windows-x86", "windows-x86_64")
for name in names:
    result = subprocess.run(
        [sys.executable, "/opt/beru/compile.py", "--target", "all", f"labs/global/{name}.c"],
        text=True, capture_output=True, timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "warning:" not in result.stderr, result.stderr
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


def expected_output(text):
    data = text.encode()
    marker = bytearray(b"SENTINEL")
    if len(data) >= 64:
        overflow = data[64:] + b"\0"
        assert len(overflow) <= len(marker)
        marker[:len(overflow)] = overflow
    return f"Copied: {len(data)} bytes\nAdjacent:" + "".join(f" {byte:02x}" for byte in marker) + "\n"


range_error = "Input too long: maximum is 63 bytes.\n"
for profile in ("unprotected", "hardened"):
    for name in names:
        binary = Path("/out") / target / profile / name
        for args in ((), ("one", "two")):
            result = execute(binary, *args)
            assert result.returncode == 2 and "Usage:" in result.stderr and not result.stdout
        for text in ("", "Beru", "A" * 62, "A" * 63, "é" * 31 + "A"):
            result = execute(binary, text)
            assert result.returncode == 0 and not result.stderr, result.stderr
            assert result.stdout == expected_output(text), result.stdout
        if name.endswith("_fixed"):
            for text in ("A" * 64, "é" * 32, "A" * 65, "A" * 71, "A" * 72, "A" * 256, "A" * 4096):
                result = execute(binary, text)
                assert result.returncode == 1 and not result.stdout
                assert result.stderr == range_error

# Assert the intended adjacent-member corruption only on the tested native
# unprotected build, without assuming behavior beyond the containing object.
for length in range(64, 72):
    binary = Path("/out") / target / "unprotected" / "buffer_overflow"
    result = execute(binary, "A" * length)
    assert result.returncode == 0 and not result.stderr, result.stderr
    assert result.stdout == expected_output("A" * length), result.stdout

for length in (64, 65, 71, 72, 256):
    binary = Path("/out") / target / "hardened" / "buffer_overflow"
    result = execute(binary, "A" * length)
    assert result.returncode < 0, (length, result.returncode, result.stderr)
    assert "buffer overflow detected" in result.stderr, result.stderr
print(f"PASS: {target} parsing, byte boundaries, adjacent corruption, fixed rejection, and fortify detection", flush=True)

# ASan redzones surround the whole global structure, not its array members.
# Use length 72 to cross the entire 72-byte object's boundary with the NUL.
prefix = {"linux-arm64": "aarch64-linux-gnu", "linux-x86_64": "x86_64-linux-gnu"}[target]
environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1")
with tempfile.TemporaryDirectory(dir="/out") as temporary:
    for name in names:
        binary = Path(temporary) / name
        subprocess.run([f"{prefix}-gcc", "-std=c11", "-O0", "-g", "-fno-omit-frame-pointer",
                        "-fsanitize=address", "-fno-pie", "-no-pie",
                        f"/src/labs/global/{name}.c", "-o", str(binary)],
                       check=True, text=True, capture_output=True, timeout=30)
        for length in (0, 63, 64, 65, 71, 72, 80, 256):
            result = execute(binary, "A" * length, env=environment)
            if name == "buffer_overflow" and length >= 72:
                assert result.returncode != 0
                assert "AddressSanitizer: global-buffer-overflow" in result.stderr, result.stderr
                assert "WRITE of size" in result.stderr, result.stderr
            else:
                rejected = name.endswith("_fixed") and length >= 64
                assert result.returncode == (1 if rejected else 0), result.stderr
                assert "AddressSanitizer" not in result.stderr
                if rejected:
                    assert result.stderr == range_error and not result.stdout
                else:
                    assert result.stdout == expected_output("A" * length) and not result.stderr
print("PASS: ASan detects writes beyond the global object; fixed source stays in bounds", flush=True)
print("PASS: 24 verified binaries; Windows and non-native CPUs receive build verification only", flush=True)
