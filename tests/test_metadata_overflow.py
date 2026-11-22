"""Cross-build the allocator metadata overflow lab and check native Linux boundaries."""

import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
from pathlib import Path


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
names = ("metadata_overflow", "metadata_overflow_fixed")
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
    assert result.returncode == 0 and not result.stderr, (result.returncode, result.stderr)
    assert result.stdout.splitlines() == [
        f"Count: {count}", "Fill: zero bytes into a 64-byte allocation",
        "Fill completed; freeing victim", "Victim free returned",
    ], result.stdout


fixed_error = "Input too long: maximum is 64 bytes.\n"
layout_error = "Layout unavailable: metadata mode requires nearby ordinary glibc chunks.\n"
for profile in ("unprotected", "hardened"):
    for name in names:
        binary = Path("/out") / target / profile / name
        for args in ((), ("0", "extra")):
            result = execute(binary, *args)
            assert result.returncode == 2 and "Usage:" in result.stderr and not result.stdout
        for count in ("", "bad", "1x", "1.0", "1 ", "-1", "9" * 100, "-" + "9" * 100):
            result = execute(binary, count)
            assert result.returncode == 2 and not result.stdout
            assert result.stderr == "Expected a nonnegative decimal count representable as long, or metadata.\n"
        for count in (0, 1, 63, 64):
            check_output(execute(binary, str(count)), count)
        for text, count in (("+64", 64), (" 1", 1), ("-0", 0)):
            check_output(execute(binary, text), count)
        for count in ((65, 66, 80, 128, 4096, 4097) if name.endswith("_fixed") else (4097, 100000)):
            result = execute(binary, str(count))
            assert result.returncode == 1 and not result.stdout
            assert result.stderr == (fixed_error if name.endswith("_fixed") else
                                     "Input too long: demonstration maximum is 4096 bytes.\n")
        result = execute(binary, "metadata")
        if result.returncode == 3:
            assert result.stderr == layout_error and not result.stdout
            print(f"SKIP: {profile}/{name} glibc layout unavailable", flush=True)
        elif name.endswith("_fixed"):
            assert result.returncode == 1 and result.stderr == fixed_error and not result.stdout
        else:
            lines = result.stdout.splitlines()
            count = int(lines[0].split(": ")[1])
            assert 64 < count <= 4096, result.stdout
            assert result.returncode < 0, (result.returncode, result.stdout, result.stderr)
            assert lines[1] == "Fill: zero bytes into a 64-byte allocation"
            if profile == "hardened":
                assert "buffer overflow detected" in result.stderr, result.stderr
                assert len(lines) == 2, result.stdout
            else:
                # The fill must return, then the allocator must reject the header.
                assert lines[2:] == ["Fill completed; freeing victim"], result.stdout
                assert "free(): invalid" in result.stderr, result.stderr
                print(f"PASS: allocator rejected corrupted metadata after {count}-byte fill", flush=True)
print(f"PASS: {target} parsing, boundaries, fixed rejection, metadata/free and fortification", flush=True)

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
            if name == "metadata_overflow" and count > 64:
                assert result.returncode != 0
                assert "AddressSanitizer: heap-buffer-overflow" in result.stderr, result.stderr
                assert "WRITE of size" in result.stderr, result.stderr
            elif count > 64:
                assert result.returncode == 1 and result.stderr == fixed_error and not result.stdout
            else:
                check_output(result, count)
        result = execute(binary, "metadata", env=environment)
        assert result.returncode == 3 and result.stderr == layout_error and not result.stdout
print("PASS: ASan detects overflow writes; instrumented layout declined; fixed source stays in bounds", flush=True)
print("PASS: 24 verified binaries; Windows and non-native CPUs receive build verification only", flush=True)
