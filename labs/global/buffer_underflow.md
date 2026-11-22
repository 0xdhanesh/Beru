# Global/static buffer underflow

This lab demonstrates a one-byte write before the start of a buffer with static storage duration. The [vulnerable source](buffer_underflow.c) checks only an index's upper bound; the [fixed source](buffer_underflow_fixed.c) checks both bounds. Both are portable C11 and build for all six targets in the repository's [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

A file-scope `static` structure contains an eight-byte marker initialized to `SENTINEL`, followed by `char buffer[64]`. A structure gives the members a specified order; compile-time assertions verify the buffer starts at offset 8 and the whole object occupies 72 bytes. The program does not rely on independently declared global variables being adjacent. Both members have static storage duration rather than living on the stack or heap.

The program accepts `INDEX BYTE`, initializes the buffer to dots, and writes the supplied byte at the requested index. Indices 0–63 are valid. The vulnerable check rejects only `index >= (long)sizeof(storage.buffer)`, so negative values reach `storage.buffer[index] = value`. Index -1 targets the marker's last byte, and index -8 targets its first byte. Index -9 is before the whole containing object. Each invocation performs one byte write rather than copying across a boundary.

This is a buffer underwrite (CWE-124), caused by improper validation of an array index (CWE-129). Accessing a negative buffer index is undefined behavior even when the affected byte belongs to another member of the containing structure. The correction rejects `index < 0 || index >= (long)sizeof(storage.buffer)` before indexing the array.

Both versions use `strtol` to reject malformed indices and values outside the platform's `long` range. An optional sign and leading whitespace are accepted; trailing characters, including whitespace, are rejected. Windows and Unix-like targets may have different `long` widths. `BYTE` must contain exactly one byte: a multibyte UTF-8 character does not qualify, and command-line arguments cannot contain embedded NULs.

The program prints exactly 64 buffer bytes with `fwrite` and exactly eight marker bytes as hexadecimal. Neither field is treated as a terminated string. Before corruption, the marker prints as `53 45 4e 54 49 4e 45 4c` (`SENTINEL`). Index -1 with byte `X` is intended to change its last byte to `58` while leaving the buffer untouched.

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target all --name global_buffer_underflow labs/global/buffer_underflow.c
./scripts/compile.sh --target all --name global_buffer_underflow_fixed labs/global/buffer_underflow_fixed.c
```

The explicit output names distinguish these binaries from the stack underflow lab. The commands produce 24 binaries: two sources, six targets, and two profiles. Binaries and verified JSON reports are under `build/<target>/<profile>/global_buffer_underflow[.exe]` and `global_buffer_underflow_fixed[.exe]`. Supported targets are Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64; macOS/BSD and Windows ARM are not compiler targets.

## Expected behavior

| Input | Vulnerable version | Fixed version |
| ----- | ------------------ | ------------- |
| Wrong argument count | Usage on stderr; exit 2 | Same |
| Malformed or overflowing index, or value not exactly one byte | Parse error on stderr; exit 2 | Same |
| Index 0–63 | Prints the buffer with the chosen byte replaced and unchanged marker; exit 0 | Same |
| Index 64 or greater within `long` range | Range error on stderr; exit 1 | Same |
| Negative representable index | Writes before the buffer; undefined behavior | Range error on stderr; exit 1 |

The vulnerable error message describes the intended range even though its check omits the lower bound. Native Linux tests verify the intended marker changes for indices -8 through -1 in both profiles. No particular result is guaranteed by C after the invalid write. More negative indices may corrupt unrelated storage, crash, or appear to work.

Stack canaries do not directly protect static storage. Library fortification does not generally check direct indexed stores, and ASLR/DEP do not replace the missing bounds check. Both normal profiles retain the bug; neither is expected to detect the tested marker underwrites. The fixed source supplies the necessary validation.

## Run in Docker

Start a shell with the built binaries mounted read-only:

```bash
docker run --rm -it --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD/build,target=/out,readonly" \
  --entrypoint /bin/bash beru-compiler:local
```

Inside the container:

```bash
case "$(uname -m)" in
  aarch64) target=linux-arm64 ;;
  x86_64) target=linux-x86_64 ;;
esac

/out/$target/unprotected/global_buffer_underflow 0 X
# Buffer: X followed by 63 dots.
# Preceding: 53 45 4e 54 49 4e 45 4c

/out/$target/unprotected/global_buffer_underflow -1 X
# Intended observation on the tested build:
# Buffer: 64 dots.
# Preceding: 53 45 4e 54 49 4e 45 58

/out/$target/hardened/global_buffer_underflow -1 X
# Same intended observation; the indexed underwrite remains undefined behavior.

/out/$target/unprotected/global_buffer_underflow_fixed -1 X
# Index out of range: expected 0 through 63.
echo "$?"
# 1
```

## Automated verification

The test builds 24 binaries and verifies their compiler reports without compiler warnings. Native Linux checks cover argument counts, malformed and overflowing numeric inputs, single-byte validation, all 64 valid indices, upper-bound rejection, marker corruption at -8 through -1 in both profiles, and fixed rejection of negative indices. Windows and non-native CPUs receive build verification only.

Separate temporary UndefinedBehaviorSanitizer builds use `-fsanitize=bounds -fno-sanitize-recover=bounds`. These checks detect negative indices at the buffer member's boundary, including indices -8 and -1 inside the containing object and -9 and -64 before it. The sanitizer stops execution before the invalid write. Tests also verify accepted indices and the fixed bounds; temporary binaries are removed afterward. Ordinary AddressSanitizer redzones around the containing object cannot reliably detect underwrites into its preceding member, so the marker bytes are checked directly in normal builds.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_global_buffer_underflow.py
```
