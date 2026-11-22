# Stack out-of-bounds read

This lab demonstrates a read beyond the end of a stack buffer. The [vulnerable source](out_of_bounds_read.c) checks only the lower bound of an index. The [fixed source](out_of_bounds_read_fixed.c) checks both bounds. Both are portable C11 and build with the repository's [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

The program accepts `INDEX` and initializes a 64-byte local array so each byte equals its index: `buffer[0]` is `0x00`, and `buffer[63]` is `0x3f`. It reads one byte at the requested index and prints it as hexadecimal. This is a raw byte array, so no string terminator is needed. All valid bytes are initialized before reading.

The vulnerable guard rejects negative indices but omits the upper bound. Index 64 reads one byte immediately beyond the array, and index 65 reads one byte two positions beyond the last valid element. Each invocation performs one indexed byte read. It does not write outside the buffer. Reading the one-past pointer is invalid even though forming that pointer is permitted in C.

The correction rejects `index < 0 || index >= (long)sizeof(buffer)` before accessing the array. This is an out-of-bounds read (CWE-125), caused by improper validation of an array index (CWE-129). Both programs parse the decimal index using `strtol`, reject malformed input and values outside the platform's `long` range, and accept an optional sign and leading whitespace. Trailing characters, including whitespace, are rejected. Windows and Unix-like targets can have different `long` widths.

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target all labs/stack/out_of_bounds_read.c
./scripts/compile.sh --target all labs/stack/out_of_bounds_read_fixed.c
```

Each source produces `unprotected` and `hardened` binaries for Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. Binaries and verified JSON reports are under `build/<target>/<profile>/out_of_bounds_read[.exe]` and `out_of_bounds_read_fixed[.exe]`. This compiler does not target macOS/BSD or Windows ARM.

## Expected behavior

| Input | Vulnerable version | Fixed version |
| ----- | ------------------ | ------------- |
| Wrong argument count | Usage on stderr; exit 2 | Usage on stderr; exit 2 |
| Invalid index syntax or value outside `long` range | Parse error on stderr; exit 2 | Parse error on stderr; exit 2 |
| Index 0–63 | Prints the index and its byte value in hexadecimal; exit 0 | Same |
| Negative representable index | Range error on stderr; exit 1 | Same |
| Index 64 or greater within `long` range | Reads beyond the stack buffer; undefined behavior | Range error on stderr; exit 1 |

The vulnerable range error describes the intended range even though its check omits the upper bound. An invalid read may print an unrelated byte, crash, or behave differently after optimization. No particular leaked value, adjacent object, or crash is guaranteed. Stack layout varies with compiler, architecture, and profile. Stack canaries detect certain overwrites and do not generally detect reads; other binary protections also do not replace the missing bounds check. The hardened profile remains vulnerable. AddressSanitizer provides separate diagnostic instrumentation for this lab.

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

/out/$target/unprotected/out_of_bounds_read 0
# Byte[0]: 0x00
/out/$target/unprotected/out_of_bounds_read 63
# Byte[63]: 0x3f
/out/$target/unprotected/out_of_bounds_read 64
# Undefined behavior; may print a byte from beyond the array or crash.
/out/$target/hardened/out_of_bounds_read 64
# Undefined behavior; hardening does not ensure detection of this read.
/out/$target/unprotected/out_of_bounds_read_fixed 64
# Index out of range: expected 0 through 63.
echo "$?"
# 1
```

## Automated verification

The test builds 24 binaries (two sources, six targets, two profiles) and verifies their compiler reports. Native Linux runtime checks cover argument errors, malformed and overflowing numeric inputs, all 64 valid indices, negative-index rejection, and fixed upper-bound rejection. Separate temporary AddressSanitizer binaries confirm one-byte stack-buffer-overflow **reads** at indices 64 and 65 and verify the fixed bounds. Sanitizer binaries are removed after testing. Ordinary vulnerable out-of-bounds execution is not asserted to crash or succeed. Windows and non-native CPUs receive build verification only.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_out_of_bounds_read.py
```
