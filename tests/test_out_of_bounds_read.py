"""Cross-build the stack out-of-bounds read lab and test its native Linux boundaries."""

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
for name in ("out_of_bounds_read", "out_of_bounds_read_fixed"):
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


range_error = "Index out of range: expected 0 through 63.\n"
parse_error = "Expected a decimal index representable as long.\n"
for profile in ("unprotected", "hardened"):
    for name in ("out_of_bounds_read", "out_of_bounds_read_fixed"):
        binary = Path("/out") / target / profile / name
        for args in ((), ("0", "extra")):
            result = execute(binary, *args)
            assert result.returncode == 2 and "Usage:" in result.stderr and not result.stdout
        for index in ("", "bad", "1x", "1.0", "9" * 100, "-" + "9" * 100):
            result = execute(binary, index)
            assert result.returncode == 2 and result.stderr == parse_error and not result.stdout
        for index in range(64):
            result = execute(binary, str(index))
            assert result.returncode == 0 and not result.stderr, result.stderr
            assert result.stdout == f"Byte[{index}]: 0x{index:02x}\n"
        # strtol accepts leading whitespace and an optional sign.
        for text, index in (("+63", 63), (" 1", 1), ("-0", 0)):
            result = execute(binary, text)
            assert result.returncode == 0 and not result.stderr
            assert result.stdout == f"Byte[{index}]: 0x{index:02x}\n"
        rejected = (-1, -2, -64, -4096)
        if name.endswith("_fixed"):
            rejected += (64, 65, 4096, 2147483647)
        for index in rejected:
            result = execute(binary, str(index))
            assert result.returncode == 1 and not result.stdout
            assert result.stderr == range_error
print(f"PASS: {target} usage, parsing, valid indices, lower-bound and fixed upper-bound rejection", flush=True)

# Do not assume canaries or fortification detect indexed reads beyond the array.
# Independent diagnostic binaries demonstrate the read with AddressSanitizer.
prefix = {"linux-arm64": "aarch64-linux-gnu", "linux-x86_64": "x86_64-linux-gnu"}[target]
environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1")
with tempfile.TemporaryDirectory(dir="/out") as temporary:
    for name in ("out_of_bounds_read", "out_of_bounds_read_fixed"):
        binary = Path(temporary) / name
        subprocess.run([f"{prefix}-gcc", "-std=c11", "-O0", "-g", "-fno-omit-frame-pointer",
                        "-fsanitize=address", "-fno-pie", "-no-pie",
                        f"/src/labs/stack/{name}.c", "-o", str(binary)],
                       check=True, text=True, capture_output=True, timeout=30)
        for index in (-2, -1, 0, 1, 62, 63, 64, 65):
            result = execute(binary, str(index), env=environment)
            if name == "out_of_bounds_read" and index >= 64:
                assert result.returncode != 0
                assert "AddressSanitizer: stack-buffer-overflow" in result.stderr, result.stderr
                assert "READ of size 1" in result.stderr, result.stderr
            else:
                expected = 1 if index < 0 or index >= 64 else 0
                assert result.returncode == expected, result.stderr
                assert "AddressSanitizer" not in result.stderr
                if expected:
                    assert result.stderr == range_error and not result.stdout
                else:
                    assert result.stdout == f"Byte[{index}]: 0x{index:02x}\n"
print("PASS: AddressSanitizer confirms one-byte reads beyond the buffer; fixed source stays in bounds", flush=True)
print("PASS: 24 verified binaries; Windows and non-native CPUs receive build verification only", flush=True)
