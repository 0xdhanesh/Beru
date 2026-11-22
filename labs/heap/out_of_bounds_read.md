# Heap out-of-bounds read

This lab demonstrates an indexed read beyond a heap allocation. The [vulnerable source](out_of_bounds_read.c) checks only the lower bound of an index, allowing reads at and beyond `malloc(64)`; the [fixed source](out_of_bounds_read_fixed.c) checks both bounds. Both are portable C11 and build for all six targets in the [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

The program parses an `INDEX`, allocates 64 bytes, initializes each byte to its index value, and prints the selected byte in hexadecimal. Indices 0–63 are valid. The vulnerable check rejects negative indices but omits the upper bound, so index 64 reads one byte beyond the requested allocation. Larger indices may disclose unrelated memory, fault, or appear to work.

The fixed version rejects `index < 0 || index >= 64` before reading. It frees the allocation after valid reads. No output from an invalid read is treated as reliable: the value is outside the object and the access is undefined behavior.

This is an out-of-bounds read (CWE-125), caused by improper validation of an array index (CWE-129). It can disclose adjacent heap contents, allocator state, or other process data. The result depends on the allocator, runtime, and build profile.

## Input and behavior

The interface is `INDEX`:

- Indices 0–63 print `Byte[INDEX]` with the deterministic initialized byte value `INDEX`.
- The vulnerable source accepts nonnegative indices beyond 63 because its upper-bound check is missing. Index 64 is the one-byte read demonstration.
- The fixed source rejects every index below 0 or at least 64.
- `INDEX` is parsed with `strtol`; malformed and overflowing values are rejected. Leading whitespace and an optional sign are accepted, while trailing characters are rejected.

The vulnerable source does not attempt to print a string or scan adjacent memory after the indexed read. AddressSanitizer provides a deterministic diagnostic for the invalid read; ordinary uninstrumented execution may print an incidental byte, crash, or expose unrelated memory.

| Condition | Vulnerable version | Fixed version |
| --------- | ------------------ | ------------- |
| Wrong argument count | Usage on stderr; exit 2 | Same |
| Malformed or overflowing index | Parse error on stderr; exit 2 | Same |
| Index 0–63 | Prints the initialized byte; exit 0 | Same |
| Negative index | Range error on stderr; exit 1 | Same |
| Index 64 or greater | One-byte or larger heap read; undefined behavior | Range error on stderr; exit 1 |
| Allocation failure | Error on stderr; exit 3 | Same |

Hardened Linux builds may not detect a direct indexed read. Stack canaries do not protect heap allocations, and ASLR/DEP do not replace the missing upper-bound check. The fixed source supplies the necessary validation.

## Build both profiles

Because the repository also contains a stack lab with the same source stem, use explicit output names:

```bash
./scripts/compile.sh --target all --name heap_out_of_bounds_read labs/heap/out_of_bounds_read.c
./scripts/compile.sh --target all --name heap_out_of_bounds_read_fixed labs/heap/out_of_bounds_read_fixed.c
```

The commands produce 24 binaries: two sources, six targets, and two profiles. Binaries and verified JSON reports are under `build/<target>/<profile>/heap_out_of_bounds_read[.exe]` and `heap_out_of_bounds_read_fixed[.exe]`. Supported targets are Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. macOS/BSD and Windows ARM are not compiler targets.

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

/out/$target/unprotected/heap_out_of_bounds_read 63
# Byte[63]: 0x3f

/out/$target/unprotected/heap_out_of_bounds_read_fixed 64
# Index out of range: expected 0 through 63.
echo "$?"
# 1
```

The 64-byte vulnerable invocation is intentionally undefined. It may print an allocator-dependent byte or terminate before producing a result.

## Automated verification

The [test](../../tests/test_heap_out_of_bounds_read.py) cross-builds both sources for all six targets and both profiles, verifies the compiler reports, and checks native Linux parsing, all valid indices, lower-bound rejection, and fixed upper-bound rejection. Temporary AddressSanitizer builds then verify one-byte heap reads beyond the allocation and confirm that the fixed source stays in bounds. Windows and non-native CPUs receive build verification only.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_heap_out_of_bounds_read.py
```
