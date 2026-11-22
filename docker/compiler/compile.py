"""Container-only GCC cross-compilation and binary profile verification."""

import argparse
import hashlib
import json
import re
import shlex
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


TARGETS = {
    "linux-x86": "i686-linux-gnu",
    "linux-x86_64": "x86_64-linux-gnu",
    "linux-arm": "arm-linux-gnueabihf",
    "linux-arm64": "aarch64-linux-gnu",
    "windows-x86": "i686-w64-mingw32",
    "windows-x86_64": "x86_64-w64-mingw32",
}


def run(command):
    return subprocess.run(command, check=True, text=True, capture_output=True).stdout


def source_path(value, directory=False):
    root = Path("/src")
    path = (root / value).resolve()
    if not path.is_relative_to(root) or not (path.is_dir() if directory else path.is_file()):
        raise ValueError(f"Expected an existing repository {'directory' if directory else 'file'}: {value}")
    return path


def flags_for(target, profile):
    hardened = profile == "hardened"
    windows = target.startswith("windows-")
    flags = ["-Wall", "-Wextra", "-U_FORTIFY_SOURCE", "-U_GLIBCXX_ASSERTIONS"]
    if hardened:
        flags += ["-O2", "-fstack-protector-all", "-ftrivial-auto-var-init=zero",
                  "-D_GLIBCXX_ASSERTIONS"]
    else:
        flags += ["-O0", "-g3", "-fno-omit-frame-pointer", "-fno-stack-protector",
                  "-ftrivial-auto-var-init=uninitialized"]

    if windows:
        # Bundle MinGW support libraries, including the stack protector runtime.
        flags += ["-static", "-Wl,--no-insert-timestamp"]
        if hardened:
            flags += ["-Wl,--dynamicbase,--nxcompat,--enable-reloc-section"]
        else:
            flags += ["-fno-pie", "-Wl,--disable-dynamicbase,--disable-nxcompat,--disable-reloc-section"]
        if target == "windows-x86_64":
            flags += ["-Wl,--high-entropy-va" if hardened else "-Wl,--disable-high-entropy-va"]
    else:
        if hardened:
            flags += ["-D_FORTIFY_SOURCE=3", "-fPIE", "-pie", "-fstack-clash-protection",
                      "-Wl,-z,relro,-z,now,-z,noexecstack", "-Wl,-z,separate-code"]
        else:
            flags += ["-fno-pie", "-no-pie", "-fno-stack-clash-protection",
                      "-Wl,-z,norelro,-z,lazy,-z,execstack"]
        if target in ("linux-x86", "linux-x86_64"):
            flags += ["-fcf-protection=full" if hardened else "-fcf-protection=none"]
        elif target == "linux-arm64":
            flags += ["-mbranch-protection=standard" if hardened else "-mbranch-protection=none"]
    return flags


def inspect(binary, target, prefix):
    symbols = run([f"{prefix}-objdump", "-t", str(binary)])
    result = {"stack_canary_reference": "__stack_chk_fail" in symbols}
    if target.startswith("linux-"):
        # Dynamic imports survive stripping; the regular symbol table does not.
        dynamic_symbols = run([f"{prefix}-objdump", "-T", str(binary)])
        result["stack_canary_reference"] = "__stack_chk_fail" in symbols + dynamic_symbols
        headers = run([f"{prefix}-readelf", "-hW", str(binary)])
        segments = run([f"{prefix}-readelf", "-lW", str(binary)])
        dynamic = run([f"{prefix}-readelf", "-dW", str(binary)])
        sections = run([f"{prefix}-readelf", "-SW", str(binary)])
        stack = next((line for line in segments.splitlines() if "GNU_STACK" in line), "")
        if not stack:
            raise ValueError("Binary has no GNU_STACK program header")
        result.update({
            "pie": bool(re.search(r"Type:\s+DYN", headers)),
            "non_executable_stack": "E" not in stack.split()[6],
            "relro": "GNU_RELRO" in segments,
            "bind_now": "BIND_NOW" in dynamic or bool(re.search(r"FLAGS.*\bNOW\b", dynamic)),
            "symbol_table": ".symtab" in sections,
            "debug_info": ".debug_info" in sections,
        })
    else:
        data = binary.read_bytes()
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("Not a PE binary")
        dll_flags = struct.unpack_from("<H", data, pe + 24 + 70)[0]
        symbol_count = struct.unpack_from("<I", data, pe + 16)[0]
        sections = run([f"{prefix}-objdump", "-h", str(binary)])
        result.update({
            "aslr": bool(dll_flags & 0x40),
            "dep_compatible": bool(dll_flags & 0x100),
            "high_entropy_aslr": bool(dll_flags & 0x20),
            "symbol_table": symbol_count != 0,
            "debug_info": ".debug_info" in sections,
        })
        if not symbol_count:
            # Statically linked canary symbols cannot be recovered after stripping.
            result["stack_canary_reference"] = None
    return result


def verify(observed, target, profile, stripped=False):
    hardened = profile == "hardened"
    keys = (["pie", "non_executable_stack", "relro", "bind_now"]
            if target.startswith("linux-") else ["aslr", "dep_compatible"])
    if target == "windows-x86_64":
        keys.append("high_entropy_aslr")
    if not stripped:
        keys.append("stack_canary_reference")
    for key in keys:
        if observed[key] != hardened:
            raise ValueError(f"{target}/{profile}: verification failed: {key}={observed[key]}")
    if stripped and (observed["symbol_table"] or observed["debug_info"]):
        raise ValueError("Hardened binary still contains symbols or debug information")
    if not hardened and not (observed["symbol_table"] and observed["debug_info"]):
        raise ValueError("Unprotected binary is missing symbols or debug information")


def compile_one(args, sources, includes, target, profile):
    prefix = TARGETS[target]
    cxx = any(path.suffix in (".cc", ".cpp", ".cxx", ".C") for path in sources)
    compiler = f"{prefix}-{'g++' if cxx else 'gcc'}"
    flags = flags_for(target, profile)
    for include in includes:
        flags += ["-I", str(include)]
    for define in args.define:
        flags += ["-D", define]
    if args.pthread:
        flags += ["-pthread"]
    name = args.name or sources[0].stem
    if target.startswith("windows-"):
        name += ".exe"
    output = Path("/out") / target / profile / name
    output.parent.mkdir(parents=True, exist_ok=True)
    # Verify temporary output first; do not publish a failed compile as a new binary.
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        binary = Path(temporary) / name
        commands = []
        objects = []
        for index, source in enumerate(sources):
            source_cxx = source.suffix != ".c"
            driver = f"{prefix}-{'g++' if source_cxx else 'gcc'}"
            obj = Path(temporary) / f"source-{index}.o"
            objects.append(str(obj))
            commands.append([driver, *flags, "-std=c++17" if source_cxx else "-std=c11",
                             "-c", str(source), "-o", str(obj)])
        commands.append([compiler, *flags, *objects, *[f"-l{lib}" for lib in args.library],
                         "-o", str(binary)])
        for command in commands:
            print(shlex.join(command), flush=True)
            result = subprocess.run(command, text=True, capture_output=True, check=True)
            if result.stderr:
                print(result.stderr, file=sys.stderr, end="")
        before_strip = inspect(binary, target, prefix)
        verify(before_strip, target, profile)
        if profile == "hardened":
            run([f"{prefix}-strip", "--strip-all", str(binary)])
        observed = inspect(binary, target, prefix)
        verify(observed, target, profile, stripped=profile == "hardened")
        report = {
            "target": target, "profile": profile,
            "compiler": run([compiler, "--version"]).splitlines()[0],
            "flags": flags, "libraries": args.library,
            "commands": commands,
            "sources": [{"path": str(path.relative_to('/src')),
                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sources],
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "before_strip": before_strip, "binary_properties": observed,
            "verification": "passed",
        }
        report_file = Path(temporary) / (name + ".json")
        report_file.write_text(json.dumps(report, indent=2) + "\n")
        binary.replace(output)
        report_file.replace(output.with_name(name + ".json"))
    print(f"Verified: {output}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=[*TARGETS, "all"], default="linux-x86_64")
    parser.add_argument("--profile", choices=["both", "unprotected", "hardened"], default="both")
    parser.add_argument("--name")
    parser.add_argument("--include", action="append", default=[])
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--library", action="append", default=[])
    parser.add_argument("--pthread", action="store_true")
    parser.add_argument("sources", nargs="+")
    args = parser.parse_args()
    try:
        sources = [source_path(value) for value in args.sources]
        includes = [source_path(value, directory=True) for value in args.include]
        if any(path.suffix not in (".c", ".cc", ".cpp", ".cxx", ".C") for path in sources):
            raise ValueError("Sources must be C or C++ files")
        if args.name and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", args.name):
            raise ValueError("--name must be a basename using letters, digits, underscores, dots, or hyphens")
        # These definitions would silently undermine the selected hardening profile.
        if any(value.split("=", 1)[0] in ("_FORTIFY_SOURCE", "_GLIBCXX_ASSERTIONS") for value in args.define):
            raise ValueError("Hardening macros are managed by the selected profile")
        if any(not re.fullmatch(r"[A-Za-z0-9_+.-]+", lib) for lib in args.library):
            raise ValueError("--library requires a library name, not linker flags")
        targets = list(TARGETS) if args.target == "all" else [args.target]
        profiles = ["unprotected", "hardened"] if args.profile == "both" else [args.profile]
        for target in targets:
            for profile in profiles:
                compile_one(args, sources, includes, target, profile)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr, end="")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
