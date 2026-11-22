# Stack buffer underflow

This lab demonstrates a write before the beginning of a stack buffer. The [vulnerable source](buffer_underflow.c) checks only the upper bound of a signed array index. The [fixed source](buffer_underflow_fixed.c) checks both bounds. Both are portable C11 and build with the repository's [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

The program accepts `INDEX BYTE`, initializes a 64-byte stack buffer to dots, and writes the supplied byte at the chosen index. Indices 0 through 63 are valid. The vulnerable guard rejects only `index >= (long)sizeof(buffer)`, allowing negative indices to reach `buffer[index] = value`. At index -1, the assignment writes one byte immediately before the array; at -2, it writes two bytes before the array. Each invocation performs one indexed byte write, rather than copying an input string across the boundary.

The correction rejects `index < 0` as well as indices at or above the capacity. This is a buffer underwrite (CWE-124), caused by improper validation of an array index (CWE-129). The comparison remains signed so negative values reach the deliberately incomplete check in the vulnerable version.

Both programs parse the decimal index with `strtol`, reject values outside the platform's `long` range and malformed numbers, and require exactly one data byte. Windows and Unix-like targets can have different `long` widths. Counts are bytes; a multibyte UTF-8 character is not a single-byte value. Command-line arguments cannot contain embedded NULs. The buffer holds raw bytes and is printed using `fwrite` with its exact capacity, avoiding an out-of-bounds string read.

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target all labs/stack/buffer_underflow.c
./scripts/compile.sh --target all labs/stack/buffer_underflow_fixed.c
```

Each source produces `unprotected` and `hardened` binaries for Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. Binaries and verified JSON reports are under `build/<target>/<profile>/buffer_underflow[.exe]` and `buffer_underflow_fixed[.exe]`. This compiler does not target macOS/BSD or Windows ARM.

## Expected behavior

| Input | Vulnerable version | Fixed version |
| ----- | ------------------ | ------------- |
| Wrong argument count | Usage on stderr; exit 2 | Usage on stderr; exit 2 |
| Invalid index syntax, index outside `long` range, or value not exactly one byte | Parse error on stderr; exit 2 | Parse error on stderr; exit 2 |
| Index 0–63 | Prints `Buffer: ` and 64 bytes with the chosen position replaced; exit 0 | Same |
| Negative representable index | Writes before the stack buffer; undefined behavior | Range error on stderr; exit 1 |
| Index 64 or greater within `long` range | Range error on stderr; exit 1 | Range error on stderr; exit 1 |

The vulnerable program's range error describes the intended range even though its check omits the lower bound. A negative index can corrupt nearby data, crash, or appear to work. Neither profile guarantees detection: stack canaries may lie on the other side of the buffer, and library fortification does not generally check direct indexed stores. Optimization and stack layout vary across targets. No particular crash, output, or return-address overwrite is assumed after an invalid write. The fixed bounds check is the source-level correction.

## Run in Docker

Start a shell with the built binaries mounted read-only:

```bash
docker run --rm -it --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD/build,target=/out,readonly" \
  --entrypoint /bin/bash beru-compiler:local
```

Inside the container, choose the native Linux target and compare indices:

```bash
case "$(uname -m)" in
  aarch64) target=linux-arm64 ;;
  x86_64) target=linux-x86_64 ;;
esac

/out/$target/unprotected/buffer_underflow 0 X
# Buffer: X followed by 63 dots.
/out/$target/unprotected/buffer_underflow 63 X
# Buffer: 63 dots followed by X.
/out/$target/unprotected/buffer_underflow -1 X
# Undefined behavior; may appear to work despite the write before the array.
/out/$target/hardened/buffer_underflow -1 X
# Undefined behavior; hardening may not detect this underflow.
/out/$target/unprotected/buffer_underflow_fixed -1 X
# Index out of range: expected 0 through 63.
echo "$?"
# 1
```

## Automated verification

The test builds 24 binaries (two sources, six targets, two profiles) and verifies their compiler reports. Native Linux runtime checks cover argument errors, malformed and overflowing numeric inputs, byte validation, valid indices including 0 and 63, upper-bound rejection, and fixed rejection of negative indices. Separate temporary AddressSanitizer binaries confirm one-byte stack-buffer-underflow writes at -1 and -2 and verify the fixed bounds. Sanitizer binaries are removed after testing. Ordinary vulnerable negative-index execution is not asserted to crash or succeed. Windows and non-native CPUs receive build verification only.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_buffer_underflow.py
```
