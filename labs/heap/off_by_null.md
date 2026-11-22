# Heap off-by-null overflow

This lab demonstrates a terminating-NUL write one byte beyond a heap allocation. The [vulnerable source](off_by_null.c) accepts 64 data bytes for `malloc(64)` and copies those bytes plus their NUL terminator; the [fixed source](off_by_null_fixed.c) reserves space for the terminator by accepting at most 63 data bytes. Both are portable C11 and build for all six targets in the [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

The program accepts one command-line string, allocates 64 bytes, and copies the input with `memcpy`. The vulnerable version rejects inputs longer than 64 bytes, but it does not reserve room for the terminator. At exactly 64 data bytes, the input occupies `buffer[0..63]` and the copied NUL is written to `buffer[64]`, one byte beyond the requested allocation. Longer inputs are rejected so the example isolates the NUL-only overflow.

The fixed version rejects inputs of length 64 or greater, leaving one byte for the terminator. It prints the data with `fwrite` using the measured input length, avoiding a second out-of-bounds read if the vulnerable copy is detected or appears to complete.

This is an off-by-one error (CWE-193) leading to a heap-based buffer overflow (CWE-122) and out-of-bounds write (CWE-787). Unlike the heap off-by-one lab, the byte beyond the allocation is always zero rather than attacker-controlled data. Its effect remains allocator- and version-dependent: the byte may land in padding, metadata, or unrelated state.

## Input and behavior

The interface is `INPUT`:

- Inputs shorter than 64 bytes are copied with their terminating NUL and printed as data.
- The vulnerable source accepts exactly 64 data bytes to demonstrate the one-byte NUL overflow.
- The fixed source accepts at most 63 data bytes and rejects 64.
- Command-line arguments cannot contain embedded NUL bytes, and lengths count bytes rather than Unicode characters.

The allocation is intentionally not paired with a second object. This keeps the lesson focused on the terminator crossing the requested allocation boundary; AddressSanitizer provides a deterministic observation even when the native allocator reserves padding after the 64 requested bytes.

| Condition | Vulnerable version | Fixed version |
| --------- | ------------------ | ------------- |
| Wrong argument count | Usage on stderr; exit 2 | Same |
| Input length 0–63 | Prints input; exit 0 | Same |
| Input length 64 | One-byte NUL heap overflow; undefined behavior | Range error on stderr; exit 1 |
| Input length above 64 | Range error on stderr; exit 1 | Range error on stderr; exit 1 |
| Allocation failure | Error on stderr; exit 3 | Same |

Hardened Linux builds may detect the invalid `memcpy` through fortification and abort before the copied data is printed. Stack canaries do not directly protect heap allocations, and ASLR/DEP do not supply the missing source-level bounds check. Windows and Unix-like runtimes can therefore show different manifestations.

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target all labs/heap/off_by_null.c
./scripts/compile.sh --target all labs/heap/off_by_null_fixed.c
```

The commands produce 24 binaries: two sources, six targets, and two profiles. Binaries and verified JSON reports are under `build/<target>/<profile>/off_by_null[.exe]` and `off_by_null_fixed[.exe]`. Supported targets are Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. macOS/BSD and Windows ARM are not compiler targets.

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

/out/$target/unprotected/off_by_null "$(python3 -c 'print("A" * 63)')"
# Copied: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

/out/$target/unprotected/off_by_null_fixed "$(python3 -c 'print("A" * 64)')"
# Input too long: maximum is 63 bytes.
echo "$?"
# 1
```

The 64-byte vulnerable invocation is intentionally undefined. On a hardened Linux build it may abort with a buffer-overflow diagnostic; on an unprotected build it may appear to complete because the allocator has padding after the requested region.

## Automated verification

The [test](../../tests/test_heap_off_by_null.py) cross-builds both sources for all six targets and both profiles, rejects compiler warnings, and checks each binary report. Native Linux checks cover usage, input-length boundaries, fixed rejection, and hardened detection. Temporary AddressSanitizer builds then verify a heap-buffer-overflow write of 65 bytes at exactly 64 data bytes and confirm that the fixed source stays in bounds. Windows and non-native CPUs receive build verification only.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_heap_off_by_null.py
```
