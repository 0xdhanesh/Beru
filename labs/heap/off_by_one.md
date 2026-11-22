# Heap off-by-one overflow

This lab demonstrates a capacity check that accepts one byte too many for a heap allocation. The [vulnerable source](off_by_one.c) writes up to 65 bytes into `malloc(64)`; the [fixed source](off_by_one_fixed.c) limits the write to the 64 requested bytes. Both are portable C11 and build for all six targets in the [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

The program parses a decimal `COUNT`, allocates 64 bytes, fills the allocation with dots, and then writes `COUNT` `X` bytes. The vulnerable version accepts counts from 0 through 65. At exactly 65, bytes 0–63 are inside the allocation and byte 64 is one byte beyond it. Counts above 65 are rejected so the example isolates a single-byte heap overflow rather than an unrestricted write.

The fixed version accepts counts from 0 through 64 and rejects 65 before allocating or writing. The buffer is treated as raw byte storage: output uses `fwrite` with the known 64-byte capacity and does not depend on a string terminator.

This is an off-by-one error (CWE-193) leading to a heap-based buffer overflow (CWE-122) and out-of-bounds write (CWE-787). The byte beyond the allocation may be allocator padding, metadata, or unrelated state. Its effect is allocator- and version-dependent; successful completion does not make the write valid.

## Input and behavior

The interface is `COUNT`:

- Numeric counts are parsed with `strtol`; negative, malformed, and overflowing values are rejected.
- Counts 0–64 print the count and a 64-byte buffer containing `X` for the written prefix and dots for the remainder.
- The vulnerable source accepts 65 solely to demonstrate the one-byte overflow. It prints the count before the write and avoids a later `free` after the invalid write.
- The fixed source rejects 65 with a range error.

The allocation is intentionally not paired with a second object. This keeps the lesson focused on crossing the requested allocation boundary; AddressSanitizer provides a deterministic observation even when the native allocator reserves padding after the 64 requested bytes.

| Condition | Vulnerable version | Fixed version |
| --------- | ------------------ | ------------- |
| Wrong argument count | Usage on stderr; exit 2 | Same |
| Malformed, negative, or overflowing count | Parse error on stderr; exit 2 | Same |
| Numeric count 0–64 | Prints buffer; exit 0 | Same |
| Numeric count 65 | One-byte heap overflow; undefined behavior | Range error on stderr; exit 1 |
| Numeric count above 65 | Demonstration-limit error on stderr; exit 1 | Range error on stderr; exit 1 |
| Allocation failure | Error on stderr; exit 3 | Same |

Hardened Linux builds may detect the invalid `memset` through fortification and abort before the buffer is printed. Stack canaries do not directly protect heap allocations, and ASLR/DEP do not supply the missing source-level bounds check. Windows and Unix-like runtimes can therefore show different manifestations.

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target all labs/heap/off_by_one.c
./scripts/compile.sh --target all labs/heap/off_by_one_fixed.c
```

The commands produce 24 binaries: two sources, six targets, and two profiles. Binaries and verified JSON reports are under `build/<target>/<profile>/off_by_one[.exe]` and `off_by_one_fixed[.exe]`. Supported targets are Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. macOS/BSD and Windows ARM are not compiler targets.

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

/out/$target/unprotected/off_by_one 64
# Count: 64
# Buffer: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

/out/$target/unprotected/off_by_one_fixed 65
# Input too long: maximum is 64 bytes.
echo "$?"
# 1
```

The 65-byte vulnerable invocation is intentionally undefined. On a hardened Linux build it may abort with a buffer-overflow diagnostic; on an unprotected build it may appear to complete because the allocator has padding after the requested region.

## Automated verification

The [test](../../tests/test_heap_off_by_one.py) cross-builds both sources for all six targets and both profiles, rejects compiler warnings, and checks each binary report. Native Linux checks cover usage, parsing, valid 0–64-byte boundaries, the vulnerable demonstration limit, and fixed rejection. Temporary AddressSanitizer builds then verify a heap-buffer-overflow write at exactly 65 bytes and confirm that the fixed source stays in bounds. Windows and non-native CPUs receive build verification only.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_heap_off_by_one.py
```
