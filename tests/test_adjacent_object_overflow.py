"""Cross-build the adjacent heap object overflow lab and check native Linux boundaries."""

import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
from pathlib import Path


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
names = ("adjacent_object_overflow", "adjacent_object_overflow_fixed")
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


def check_output(result, count, callback="original"):
    assert result.returncode == 0 and not result.stderr, (result.returncode, result.stderr)
    lines = result.stdout.splitlines()
    assert len(lines) == 4, result.stdout
    assert lines[0] == f"Count: {count}"
    assert lines[1].startswith("Forward distance: ")
    assert int(lines[2].split(": ")[1]) in (4, 8), result.stdout
    assert lines[3] == f"Callback: {callback}", result.stdout


fixed_error = "Input too long: maximum is 64 bytes.\n"
layout_error = "Layout unavailable: callback is not within the forward demonstration range.\n"
for profile in ("unprotected", "hardened"):
    for name in names:
        binary = Path("/out") / target / profile / name
        for values in ((), ("0", "extra")):
            result = execute(binary, *values)
            assert result.returncode == 2 and "Usage:" in result.stderr and not result.stdout
        for count in ("", "bad", "1x", "1.0", "1 ", "-1", "9" * 100, "-" + "9" * 100):
            result = execute(binary, count)
            assert result.returncode == 2 and not result.stdout
            assert result.stderr == "Expected a nonnegative decimal count representable as long, or adjacent.\n"
        for count in (0, 1, 31, 63, 64):
            check_output(execute(binary, str(count)), count)
        for text, count in (("+64", 64), (" 1", 1), ("-0", 0)):
            check_output(execute(binary, text), count)
        for count in ((65, 66, 80, 81, 4096, 4097) if name.endswith("_fixed") else (4097, 100000)):
            result = execute(binary, str(count))
            assert result.returncode == 1 and not result.stdout
            assert result.stderr == (fixed_error if name.endswith("_fixed") else
                                     "Input too long: demonstration maximum is 4096 bytes.\n")
        result = execute(binary, "adjacent")
        if result.returncode == 3:
            assert result.stderr == layout_error and not result.stdout
            print(f"SKIP: {profile}/{name} forward-layout observation unavailable", flush=True)
        elif name.endswith("_fixed"):
            assert result.returncode == 1 and result.stderr == fixed_error and not result.stdout
        elif profile == "hardened":
            assert result.returncode < 0 and "buffer overflow detected" in result.stderr, result.stderr
        else:
            # Count is selected from this process's actual allocation addresses.
            # No fixed allocator chunk size or address is assumed.
            assert result.returncode == 0, (result.returncode, result.stderr)
            lines = result.stdout.splitlines()
            distance = int(lines[1].split(": ")[1])
            assert 64 <= distance < 4096
            width = int(lines[2].split(": ")[1])
            assert distance + width <= 4096
            check_output(result, distance + width, callback="replacement")
            print(f"PASS: adjacent callback redirected at observed distance {distance}", flush=True)
print(f"PASS: {target} usage, parsing, copy boundaries, fixed rejection, and layout-aware checks", flush=True)

prefix = {"linux-arm64": "aarch64-linux-gnu", "linux-x86_64": "x86_64-linux-gnu"}[target]
environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1")
with tempfile.TemporaryDirectory(dir="/out") as temporary:
    for name in names:
        binary = Path(temporary) / name
        subprocess.run([f"{prefix}-gcc", "-std=c11", "-O0", "-g", "-fno-omit-frame-pointer",
                        "-fsanitize=address", "-fno-pie", "-no-pie",
                        f"/src/labs/heap/{name}.c", "-o", str(binary)],
                       check=True, text=True, capture_output=True, timeout=30)
        for count in (0, 63, 64, 65, 66, 128):
            result = execute(binary, str(count), env=environment)
            if name == "adjacent_object_overflow" and count > 64:
                assert result.returncode != 0
                assert "AddressSanitizer: heap-buffer-overflow" in result.stderr, result.stderr
                assert "WRITE of size" in result.stderr, result.stderr
            elif count > 64:
                assert result.returncode == 1 and result.stderr == fixed_error and not result.stdout
            else:
                check_output(result, count)
print("PASS: ASan detects heap writes beyond 64 bytes; fixed source stays in bounds", flush=True)
print("PASS: 24 verified binaries; Windows and non-native CPUs receive build verification only", flush=True)
