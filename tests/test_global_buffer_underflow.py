"""Cross-build the static underflow lab and test native Linux boundaries."""

import json
import platform
import resource
import subprocess
import sys
import tempfile
from pathlib import Path


resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
names = ("buffer_underflow", "buffer_underflow_fixed")
targets = ("linux-x86", "linux-x86_64", "linux-arm", "linux-arm64",
           "windows-x86", "windows-x86_64")
for name in names:
    result = subprocess.run(
        [sys.executable, "/opt/beru/compile.py", "--target", "all", "--name", f"global_{name}",
         f"labs/global/{name}.c"],
        text=True, capture_output=True, timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "warning:" not in result.stderr, result.stderr
    for target in targets:
        for profile in ("unprotected", "hardened"):
            filename = "global_" + name + (".exe" if target.startswith("windows-") else "")
            report = Path("/out") / target / profile / (filename + ".json")
            assert json.loads(report.read_text())["verification"] == "passed"
    print(f"PASS: global {name}, six targets, two verified profiles", flush=True)

native = {"aarch64": "linux-arm64", "arm64": "linux-arm64", "x86_64": "linux-x86_64"}
target = native.get(platform.machine().lower())
if target is None:
    raise AssertionError(f"Unsupported runtime test architecture: {platform.machine()}")


def execute(binary, *args):
    return subprocess.run([str(binary), *args], text=True, capture_output=True, timeout=5)


def expected_output(index, value):
    buffer = list("." * 64)
    marker = bytearray(b"SENTINEL")
    if index < 0:
        assert -8 <= index < 0
        marker[8 + index] = ord(value)
    else:
        buffer[index] = value
    return ("Buffer: " + "".join(buffer) + "\nPreceding:" +
            "".join(f" {byte:02x}" for byte in marker) + "\n")


range_error = "Index out of range: expected 0 through 63.\n"
parse_error = "Expected a decimal index representable as long and exactly one data byte.\n"
for profile in ("unprotected", "hardened"):
    for name in names:
        binary = Path("/out") / target / profile / ("global_" + name)
        for args in ((), ("0",), ("0", "X", "extra")):
            result = execute(binary, *args)
            assert result.returncode == 2 and "Usage:" in result.stderr and not result.stdout
        for index in ("", "bad", "1x", "1.0", "1 ", "9" * 100, "-" + "9" * 100):
            result = execute(binary, index, "X")
            assert result.returncode == 2 and result.stderr == parse_error and not result.stdout
        for value in ("", "XY", "é"):
            result = execute(binary, "0", value)
            assert result.returncode == 2 and result.stderr == parse_error and not result.stdout
        for index in range(64):
            result = execute(binary, str(index), "X")
            assert result.returncode == 0 and not result.stderr, result.stderr
            assert result.stdout == expected_output(index, "X"), result.stdout
        for text, index, value in (("+63", 63, "%"), (" 1", 1, "!"), ("-0", 0, "Z")):
            result = execute(binary, text, value)
            assert result.returncode == 0 and not result.stderr
            assert result.stdout == expected_output(index, value)
        rejected = (64, 65, 4096, sys.maxsize)
        if name.endswith("_fixed"):
            rejected += (-1, -2, -8, -9, -64, -4096, -sys.maxsize - 1)
        else:
            # Assert intended member corruption only for the tested native build.
            # Do not execute unchecked writes outside the containing object here.
            for index in range(-8, 0):
                result = execute(binary, str(index), "X")
                assert result.returncode == 0 and not result.stderr, result.stderr
                assert result.stdout == expected_output(index, "X"), result.stdout
        for index in rejected:
            result = execute(binary, str(index), "X")
            assert result.returncode == 1 and not result.stdout
            assert result.stderr == range_error
print(f"PASS: {target} parsing, all valid indices, preceding marker corruption, and fixed bounds", flush=True)

# Bounds instrumentation checks the array member's actual boundary. Ordinary
# ASan global redzones cannot reliably catch underwrites into another member.
prefix = {"linux-arm64": "aarch64-linux-gnu", "linux-x86_64": "x86_64-linux-gnu"}[target]
with tempfile.TemporaryDirectory(dir="/out") as temporary:
    for name in names:
        binary = Path(temporary) / name
        subprocess.run([f"{prefix}-gcc", "-std=c11", "-O0", "-g",
                        "-fsanitize=bounds", "-fno-sanitize-recover=bounds",
                        f"/src/labs/global/{name}.c", "-o", str(binary)],
                       check=True, text=True, capture_output=True, timeout=30)
        for index in (-64, -9, -8, -2, -1, 0, 1, 62, 63, 64, 65):
            result = execute(binary, str(index), "X")
            if name == "buffer_underflow" and index < 0:
                assert result.returncode != 0
                assert f"runtime error: index {index} out of bounds" in result.stderr, result.stderr
                assert "char [64]" in result.stderr, result.stderr
                assert not result.stdout
            else:
                rejected = index < 0 or index >= 64
                assert result.returncode == (1 if rejected else 0), result.stderr
                if rejected:
                    assert result.stderr == range_error and not result.stdout
                else:
                    assert not result.stderr and result.stdout == expected_output(index, "X")
print("PASS: UBSan detects negative array indices; fixed source stays in bounds", flush=True)
print("PASS: 24 verified binaries; Windows and non-native CPUs receive build verification only", flush=True)
