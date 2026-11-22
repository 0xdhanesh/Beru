"""Build Windows x86 SEH labs; optionally run boundary checks on Windows.

Container: python3 /src/tests/test_seh_overwrite.py
Windows:   py tests/test_seh_overwrite.py --runtime-only --build-dir build
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--runtime-only", action="store_true")
parser.add_argument("--build-dir", type=Path, default=Path("/out"))
args = parser.parse_args()
names = ("seh_overwrite", "seh_overwrite_fixed")
profiles = ("unprotected", "hardened")

if args.runtime_only and sys.platform != "win32":
    parser.error("--runtime-only requires Windows with support for 32-bit x86 programs")

if not args.runtime_only:
    for name in names:
        result = subprocess.run(
            [sys.executable, "/opt/beru/compile.py", "--target", "windows-x86",
             f"labs/windows/{name}.c"],
            text=True, capture_output=True, timeout=180,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "warning:" not in result.stderr, result.stderr
        for profile in profiles:
            binary = args.build_dir / "windows-x86" / profile / (name + ".exe")
            report = json.loads(binary.with_suffix(".exe.json").read_text())
            assert report["verification"] == "passed"
            assert report["target"] == "windows-x86" and report["profile"] == profile
        print(f"PASS: {name}, Windows x86, two verified profiles", flush=True)

        # The classic linked-list SEH layout must not silently become an x64
        # or Unix-like demonstration with a different exception ABI.
        for prefix in ("x86_64-w64-mingw32", "i686-linux-gnu", "x86_64-linux-gnu",
                       "arm-linux-gnueabihf", "aarch64-linux-gnu"):
            result = subprocess.run(
                [prefix + "-gcc", "-std=c11", "-fsyntax-only", f"/src/labs/windows/{name}.c"],
                text=True, capture_output=True, timeout=30,
            )
            assert result.returncode != 0
            assert "This lab requires Windows x86" in result.stderr, result.stderr
    print("PASS: both sources reject all five unsupported compiler targets", flush=True)

if sys.platform != "win32":
    print("SKIP: Windows x86 runtime unavailable; build verification only", flush=True)
    sys.exit(0)


def execute(binary, *values):
    return subprocess.run([str(binary), *values], text=True, capture_output=True, timeout=5)


def output(length, next_state="unchanged", handler_state="unchanged"):
    return f"Copied: {length} bytes\nNext: {next_state}\nHandler: {handler_state}\n"


for profile in profiles:
    for name in names:
        binary = args.build_dir / "windows-x86" / profile / (name + ".exe")
        for values in ((), ("one", "two")):
            result = execute(binary, *values)
            assert result.returncode == 2 and "Usage:" in result.stderr and not result.stdout
        for length in (0, 1, 31, 63, 64):
            result = execute(binary, "A" * length)
            assert result.returncode == 0 and not result.stderr, result.stderr
            assert result.stdout == output(length), result.stdout
        fixed = name.endswith("_fixed")
        for length in ((65, 66, 68, 69, 71, 72, 73, 256, 4096) if fixed else (73, 256, 4096)):
            result = execute(binary, "A" * length)
            assert result.returncode == 1 and not result.stdout
            expected = ("Input too long: maximum is 64 bytes.\n" if fixed else
                        "Input too long: demonstration maximum is 72 bytes.\n")
            assert result.stderr == expected, result.stderr
        if not fixed:
            for length in range(65, 73):
                observed = []
                # A partial pointer overwrite may coincidentally preserve a byte.
                # Two different fill bytes ensure each touched field changes in
                # at least one run without assuming any particular stack address.
                for byte in ("A", "B"):
                    result = execute(binary, byte * length)
                    assert result.returncode == 0 and not result.stderr, result.stderr
                    assert result.stdout.startswith(f"Copied: {length} bytes\n")
                    assert len(result.stdout.splitlines()) == 3, result.stdout
                    assert result.stdout.splitlines()[1] in ("Next: changed", "Next: unchanged")
                    assert result.stdout.splitlines()[2] in ("Handler: changed", "Handler: unchanged")
                    observed.append(result.stdout)
                assert any("Next: changed" in text for text in observed), observed
                if length <= 68:
                    assert all("Handler: unchanged" in text for text in observed), observed
                else:
                    assert any("Handler: changed" in text for text in observed), observed
print("PASS: Windows x86 boundaries, record-field corruption, chain restoration, and fixed rejection")
