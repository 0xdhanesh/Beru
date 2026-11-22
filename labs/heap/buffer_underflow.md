# Heap buffer underflow

This lab demonstrates a write before the start of a heap allocation. The [vulnerable source](buffer_underflow.c) checks only the upper bound of an index, allowing a negative index to write before `malloc(64)`; the [fixed source](buffer_underflow_fixed.c) checks both bounds. Both are portable C11 and build for all six targets in the [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

The program accepts `INDEX BYTE`, allocates 64 bytes, initializes the allocation with dots, and writes the supplied byte at the requested index. Indices 0–63 are valid. The vulnerable check rejects only `index >= 64`, so `-1` reaches `buffer[-1]` and writes one byte immediately before the allocation. More negative indices may reach unrelated storage or fault.

The fixed version rejects `index < 0 || index >= 64` before indexing the allocation. Each invocation performs one byte write rather than copying across a boundary. The output prints only the valid 64-byte allocation, so it does not depend on reading nearby memory.

This is a buffer underwrite (CWE-124), caused by improper validation of an array index (CWE-129), and is an out-of-bounds write (CWE-787). The write before a heap object is undefined behavior even when the allocator has metadata or padding nearby. Its manifestation depends on the allocator, runtime, and build profile.

## Input and behavior

The interface is `INDEX BYTE`:

- Indices 0–63 print the 64-byte buffer with the selected byte replacing the dot at that position.
- The vulnerable source accepts negative indices because its lower-bound check is missing. `-1` is the one-byte-underflow demonstration; the resulting execution is undefined.
- The fixed source rejects every negative index with a range error.
- `INDEX` is parsed with `strtol`; malformed and overflowing values are rejected. `BYTE` must contain exactly one byte.

The vulnerable source avoids a later `free` after a negative-index write because allocator state may have been damaged. AddressSanitizer provides a deterministic diagnostic for the underflow; ordinary uninstrumented execution may appear to complete, crash, or corrupt allocator state.

| Condition | Vulnerable version | Fixed version |
| --------- | ------------------ | ------------- |
| Wrong argument count | Usage on stderr; exit 2 | Same |
| Malformed or overflowing index, or invalid byte | Parse error on stderr; exit 2 | Same |
| Index 0–63 | Prints the buffer; exit 0 | Same |
| Index 64 or greater | Range error on stderr; exit 1 | Same |
| Negative index | One-byte heap underflow at -1; undefined behavior | Range error on stderr; exit 1 |
| Allocation failure | Error on stderr; exit 3 | Same |

Hardened Linux builds may not detect a direct indexed underwrite. Stack canaries do not protect heap allocations, and ASLR/DEP do not replace the missing lower-bound check. The fixed source supplies the necessary validation.

## Build both profiles

Because the repository also contains stack and global labs with the same source stem, use explicit output names:

```bash
./scripts/compile.sh --target all --name heap_buffer_underflow labs/heap/buffer_underflow.c
./scripts/compile.sh --target all --name heap_buffer_underflow_fixed labs/heap/buffer_underflow_fixed.c
```

The commands produce 24 binaries: two sources, six targets, and two profiles. Binaries and verified JSON reports are under `build/<target>/<profile>/heap_buffer_underflow[.exe]` and `heap_buffer_underflow_fixed[.exe]`. Supported targets are Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. macOS/BSD and Windows ARM are not compiler targets.

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

/out/$target/unprotected/heap_buffer_underflow 0 X
# Buffer: X followed by 63 dots.

/out/$target/unprotected/heap_buffer_underflow_fixed -1 X
# Index out of range: expected 0 through 63.
echo "$?"
# 1
```

The `-1` vulnerable invocation is intentionally undefined. It may appear to complete on an unprotected build because the byte lands in allocator-managed space, or it may crash or damage allocator state.

## Automated verification

The [test](../../tests/test_heap_buffer_underflow.py) cross-builds both sources for all six targets and both profiles, verifies the compiler reports, and checks native Linux parsing, valid indices, upper-bound rejection, and fixed lower-bound rejection. Temporary AddressSanitizer builds then verify one-byte heap-buffer-underflow writes at negative indices and confirm that the fixed source stays in bounds. Windows and non-native CPUs receive build verification only.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_heap_buffer_underflow.py
```
