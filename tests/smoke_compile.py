"""Run inside the compiler container; inspect binaries without executing them."""

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path


TARGETS = {
    "linux-x86": (1, 3),
    "linux-x86_64": (2, 62),
    "linux-arm": (1, 40),
    "linux-arm64": (2, 183),
    "windows-x86": (None, 0x14C),
    "windows-x86_64": (None, 0x8664),
}


def compile_args(*args, success=True):
    result = subprocess.run([sys.executable, "/opt/beru/compile.py", *args],
                            text=True, capture_output=True)
    if (result.returncode == 0) != success:
        raise AssertionError(result.stdout + result.stderr)
    return result


for fixture, name in (("hello.c", "smoke-c"), ("hello.cpp", "smoke-cpp")):
    compile_args("--target", "all", "--name", name, f"tests/fixtures/{fixture}")
    for target, (elf_class, machine) in TARGETS.items():
        for profile in ("unprotected", "hardened"):
            output = Path("/out") / target / profile / (name + (".exe" if elf_class is None else ""))
            data = output.read_bytes()
            if elf_class is not None:
                assert data[:4] == b"\x7fELF" and data[4] == elf_class
                assert struct.unpack_from("<H", data, 18)[0] == machine
            else:
                pe = struct.unpack_from("<I", data, 0x3C)[0]
                assert struct.unpack_from("<H", data, pe + 4)[0] == machine
            report = json.loads(output.with_name(output.name + ".json").read_text())
            assert report["verification"] == "passed"
            assert report["sha256"] == hashlib.sha256(data).hexdigest()
            assert report["before_strip"]["stack_canary_reference"] == (profile == "hardened")
            if profile == "hardened":
                assert report["binary_properties"]["stack_canary_reference"] == (None if elf_class is None else True)
            assert report["binary_properties"]["symbol_table"] == (profile == "unprotected")
            assert report["binary_properties"]["debug_info"] == (profile == "unprotected")
    print(f"PASS: {fixture}, six targets, two profiles", flush=True)

compile_args("--target", "all", "--name", "smoke-mixed", "tests/fixtures/mixed.cpp",
             "tests/fixtures/helper.c", "--include", "tests/fixtures", "--define", "BERU_TEST=1",
             "--pthread")
print("PASS: mixed C/C++ multi-source compilation and thread option", flush=True)

for args in (
    ["--target", "windows-arm64", "tests/fixtures/hello.c"],
    ["../etc/passwd"],
    ["missing.c"],
    ["--name", "../escape", "tests/fixtures/hello.c"],
    ["--define", "_FORTIFY_SOURCE=0", "tests/fixtures/hello.c"],
    ["--library=-Wl,evil", "tests/fixtures/hello.c"],
):
    compile_args(*args, success=False)

existing = Path("/out/linux-x86_64/unprotected/smoke-c")
before = existing.read_bytes()
compile_args("--name", "smoke-c", "--library", "beru_missing_library", "tests/fixtures/hello.c",
             success=False)
assert existing.read_bytes() == before
print("PASS: invalid inputs fail, failed linking preserves previous output", flush=True)
print("PASS: 36 verified binaries; no generated program was executed", flush=True)
