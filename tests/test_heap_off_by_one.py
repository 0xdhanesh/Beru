"""Cross-build the heap off-by-one lab and test native Linux boundaries."""

import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
from pathlib import Path


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
names = ("off_by_one", "off_by_one_fixed")
targets = ("linux-x86", "linux-x86_64", "linux-arm", "linux-arm64",
           "windows-x86", "windows-x86_64")
for name in names:
    result = subprocess.run(
        [sys.executable, "/opt/beru/compile.py", "--target", "all", f"labs/heap/{name}.c"],
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


def check_output(result, count):
    assert result.returncode == 0 and not result.stderr, result.stderr
    assert result.stdout == (
        f"Count: {count}\n"
        + "Buffer: "
        + "X" * count
        + "." * (64 - count)
        + "\n"
    ), result.stdout


parse_error = "Expected a nonnegative decimal count representable as long.\n"
for profile in ("unprotected", "hardened"):
    for name in names:
        binary = Path("/out") / target / profile / name
        for args in ((), ("0", "extra")):
            result = execute(binary, *args)
            assert result.returncode == 2 and "Usage:" in result.stderr and not result.stdout
        for count in ("", "bad", "1x", "1.0", "1 ", "-1", "9" * 100, "-" + "9" * 100):
            result = execute(binary, count)
            assert result.returncode == 2 and not result.stdout
            assert result.stderr == parse_error
        for count in (0, 1, 63, 64):
            check_output(execute(binary, str(count)), count)
        for text, count in (("+64", 64), (" 1", 1), ("-0", 0)):
            check_output(execute(binary, text), count)
        rejected = (65, 66, 256, 4096) if name.endswith("_fixed") else (66, 256, 4096)
        maximum = 64 if name.endswith("_fixed") else 65
        for count in rejected:
            result = execute(binary, str(count))
            assert result.returncode == 1 and not result.stdout
            expected = ("Input too long: maximum is 64 bytes.\n" if name.endswith("_fixed") else
                        "Input too long: demonstration maximum is 65 bytes.\n")
            assert result.stderr == expected
print(f"PASS: {target} usage, parsing, safe boundaries, and fixed rejection", flush=True)

prefix = {"linux-arm64": "aarch64-linux-gnu", "linux-x86_64": "x86_64-linux-gnu"}[target]
environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1")
with tempfile.TemporaryDirectory(dir="/out") as temporary:
    for name in names:
        binary = Path(temporary) / name
        subprocess.run([f"{prefix}-gcc", "-std=c11", "-O0", "-g", "-fno-omit-frame-pointer",
                        "-fsanitize=address", "-fno-pie", "-no-pie",
                        f"/src/labs/heap/{name}.c", "-o", str(binary)],
                       check=True, text=True, capture_output=True, timeout=30)
        for count in (0, 63, 64, 65):
            result = execute(binary, str(count), env=environment)
            if name == "off_by_one" and count == 65:
                assert result.returncode != 0
                assert "AddressSanitizer: heap-buffer-overflow" in result.stderr, result.stderr
                assert "WRITE of size 65" in result.stderr, result.stderr
            elif name.endswith("_fixed") and count == 65:
                assert result.returncode == 1 and result.stderr == "Input too long: maximum is 64 bytes.\n"
            else:
                check_output(result, count)
print("PASS: AddressSanitizer confirms overflow only at 65 bytes; fixed source stays in bounds", flush=True)
print("PASS: 24 verified binaries; Windows and non-native CPUs receive build verification only", flush=True)
