# Classic stack buffer overflow

This lab demonstrates an unchecked `strcpy` into a 64-byte stack buffer. It accepts one command-line string, copies it, and prints `Copied: <input>`. The [vulnerable source](classic_overflow.c) and [length-checked correction](classic_overflow_fixed.c) are portable C11 and build for all six targets in the [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

`copy_input` allocates `char buffer[64]` on the stack and passes it to `strcpy` without checking the input length. A string of 63 bytes fits with its terminating NUL. A string of 64 bytes writes its NUL beyond the buffer; longer strings also overwrite adjacent bytes. Counts are bytes, so multibyte text may reach the limit with fewer than 64 characters. Command-line strings cannot contain embedded NUL bytes.

This is [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html), caused by [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html). The fixed implementation checks `strlen(input) >= sizeof(buffer)`, rejects oversized input, and copies the accepted length plus its NUL with `memcpy`. It preserves the accepted string without truncation.

## Build both profiles

Run these commands from the repository root:

```bash
./scripts/compile.sh --target all labs/stack/classic_overflow.c
./scripts/compile.sh --target all labs/stack/classic_overflow_fixed.c
```

Each command produces an unprotected binary with debug symbols and a stripped hardened binary for Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. Outputs and verified protection reports are under `build/<target>/<profile>/`. Windows binary names end in `.exe`. This compiler does not target macOS/BSD or Windows ARM.

## Compare behavior in Docker

The following starts a shell in the compiler image with the generated binaries mounted read-only. Choose the target matching the container CPU: `linux-arm64` on ARM64 Docker engines or `linux-x86_64` on AMD64 engines.

```bash
docker run --rm -it --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD/build,target=/out,readonly" \
  --entrypoint /bin/bash beru-compiler:local
```

Inside that shell:

```bash
case "$(uname -m)" in
  aarch64) target=linux-arm64 ;;
  x86_64) target=linux-x86_64 ;;
esac

/out/$target/unprotected/classic_overflow Beru
# Copied: Beru

input="$(python3 -c 'print("A" * 256)')"
/out/$target/unprotected/classic_overflow "$input"
# Undefined behavior: may crash, print corrupted data, or appear to work.

/out/$target/hardened/classic_overflow "$input"
# Linux/glibc build: aborts with a buffer overflow or stack smashing diagnostic.

/out/$target/unprotected/classic_overflow_fixed "$input"
# Input too long: maximum is 63 bytes.
echo "$?"
# 1
```

| Input | Vulnerable program | Fixed program |
| ----- | ------------------ | ------------- |
| Missing argument or more than one argument | Usage on stderr; exit 2 | Usage on stderr; exit 2 |
| Empty string through 63 bytes | Prints the copied string; exit 0 | Prints the copied string; exit 0 |
| 64 bytes or more | Out-of-bounds write in the unchecked source; observed behavior depends on the build | Rejects input on stderr; exit 1 |

On hardened Linux/glibc builds, [source fortification](https://sourceware.org/glibc/manual/latest/html_node/Source-Fortification.html) can replace `strcpy` with a checked call that aborts before the invalid copy. Windows uses the compiler profile's stack canaries instead of glibc fortification; exact detection and termination behavior differ. A crash, its offset, or an overwritten return address is not guaranteed. Stack layout and optimization vary across targets. The fixed program is the source-level correction; hardening does not make the unchecked source correct.

## Automated verification

This test compiles both sources for all six targets and both profiles (24 binaries). It verifies the compiler reports, then executes the native Linux binaries inside Docker to test usage errors, empty and 63-byte inputs, rejection at 64 bytes and above in the fixed program, and hardened overflow detection. It also checks that the native unprotected vulnerable binary retains an unchecked `strcpy` reference. It does not assume a deterministic result for an unprotected overflow. Runtime behavior on Windows and non-native CPUs is not tested.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_classic_overflow.py
```
