"""Cross-build the heap out-of-bounds read lab and test native Linux boundaries."""

import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
from pathlib import Path


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
names = ("out_of_bounds_read", "out_of_bounds_read_fixed")
targets = ("linux-x86", "linux-x86_64", "linux-arm", "linux-arm64",
           "windows-x86", "windows-x86_64")
for name in names:
    output_name = "heap_" + name
    result = subprocess.run(
        [sys.executable, "/opt/beru/compile.py", "--target", "all", "--name", output_name,
         f"labs/heap/{name}.c"],
        text=True, capture_output=True, timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "warning:" not in result.stderr, result.stderr
    for target in targets:
        for profile in ("unprotected", "hardened"):
            filename = output_name + (".exe" if target.startswith("windows-") else "")
            report = Path("/out") / target / profile / (filename + ".json")
            assert json.loads(report.read_text())["verification"] == "passed"
    print(f"PASS: {output_name}, six targets, two verified profiles", flush=True)

native = {"aarch64": "linux-arm64", "arm64": "linux-arm64", "x86_64": "linux-x86_64"}
target = native.get(platform.machine().lower())
if target is None:
    raise AssertionError(f"Unsupported runtime test architecture: {platform.machine()}")


def execute(binary, *args, env=None):
    return subprocess.run([str(binary), *args], text=True, capture_output=True, timeout=5, env=env)


range_error = "Index out of range: expected 0 through 63.\n"
parse_error = "Expected a decimal index representable as long.\n"
for profile in ("unprotected", "hardened"):
    for name in names:
        binary = Path("/out") / target / profile / ("heap_" + name)
        for args in ((), ("0", "extra")):
            result = execute(binary, *args)
            assert result.returncode == 2 and "Usage:" in result.stderr and not result.stdout
        for index in ("", "bad", "1x", "1.0", "1 ", "9" * 100, "-" + "9" * 100):
            result = execute(binary, index)
            assert result.returncode == 2 and result.stderr == parse_error and not result.stdout
        for index in range(64):
            result = execute(binary, str(index))
            assert result.returncode == 0 and not result.stderr, result.stderr
            assert result.stdout == f"Byte[{index}]: 0x{index:02x}\n"
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

prefix = {"linux-arm64": "aarch64-linux-gnu", "linux-x86_64": "x86_64-linux-gnu"}[target]
environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1")
with tempfile.TemporaryDirectory(dir="/out") as temporary:
    for name in names:
        binary = Path(temporary) / name
        subprocess.run([f"{prefix}-gcc", "-std=c11", "-O0", "-g", "-fno-omit-frame-pointer",
                        "-fsanitize=address", "-fno-pie", "-no-pie",
                        f"/src/labs/heap/{name}.c", "-o", str(binary)],
                       check=True, text=True, capture_output=True, timeout=30)
        for index in (-1, 0, 1, 62, 63, 64, 65):
            result = execute(binary, str(index), env=environment)
            if name == "out_of_bounds_read" and index >= 64:
                assert result.returncode != 0
                assert "AddressSanitizer: heap-buffer-overflow" in result.stderr, result.stderr
                assert "READ of size 1" in result.stderr, result.stderr
            else:
                rejected = index < 0 or index >= 64
                assert result.returncode == (1 if rejected else 0), result.stderr
                assert "AddressSanitizer" not in result.stderr
                if rejected:
                    assert result.stderr == range_error and not result.stdout
                else:
                    assert result.stdout == f"Byte[{index}]: 0x{index:02x}\n"
print("PASS: AddressSanitizer confirms reads beyond the allocation; fixed source stays in bounds", flush=True)
print("PASS: 24 verified binaries; Windows and non-native CPUs receive build verification only", flush=True)
