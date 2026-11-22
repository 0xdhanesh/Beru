# Heap overflow: data in another allocation

This lab demonstrates an unchecked write beyond a heap buffer into data in a separately allocated object. The [vulnerable source](adjacent_data_overflow.c) omits a destination-capacity check; the [fixed source](adjacent_data_overflow_fixed.c) enforces it. Both are C11 and build for all six targets in the repository's [Docker compiler](../../docker/compiler/README.md). Observing corruption of the second allocation depends on the allocator and runtime layout.

## The bug and correction

The program makes two separate allocations: `malloc(64)` for a buffer and `malloc(8)` for a marker. It initializes the buffer to dots and the marker to `SENTINEL`. These are distinct allocations, not members inside one allocation. It then performs `memset(buffer, BYTE, COUNT)` and prints the buffer and the marker's eight bytes. The vulnerable version checks only a 4096-byte demonstration limit, not the destination allocation's 64-byte capacity.

Counts 0–64 are valid. A count of 65 writes one byte beyond the allocation, even if the allocator internally reserves more space. Larger writes may cross padding or allocator metadata before reaching the next allocation. This is a heap-based buffer overflow (CWE-122) and out-of-bounds write (CWE-787). The fixed version rejects counts greater than 64 before the write. All 64 bytes are usable because this is a raw byte fill with no string terminator.

The marker is printed as hexadecimal, so the program never reads it as a terminated string. Its initial representation is `53 45 4e 54 49 4e 45 4c`. A write reaching its first byte with `X` is intended to produce `58 45 4e 54 49 4e 45 4c`. The buffer is printed with `fwrite` using exactly its 64-byte capacity.

## Allocator layout and input modes

Two consecutive `malloc` calls do not guarantee adjacent objects, a particular ordering, or a fixed distance. Padding, metadata, size classes, separate arenas, and runtime instrumentation can change their placement. The program compares `uintptr_t` address representations and, when the marker has a higher address, reports their forward distance. It does not subtract unrelated C pointers. The address interpretation is intended for the flat-address Windows and Linux targets supported by this compiler.

The interface is `COUNT|adjacent BYTE`:

- A numeric `COUNT` selects the raw byte-fill length. The vulnerable program permits 0–4096; the fixed program permits 0–64. A numeric overflow remains invalid regardless of where the marker was allocated and may never reach it.
- `adjacent` measures the layout in the current process. If the marker starts 64–4095 bytes after the buffer, it selects `COUNT = distance + 1`, reaching the marker's first byte. Otherwise, it reports layout unavailable and exits without the fill. The fixed version performs the same layout check, then rejects the selected count because it exceeds 64.

The forward-distance check finds a nearby later allocation; it does not prove the two allocations are consecutive allocator chunks or that intervening bytes are safe to overwrite. The observed native Linux ARM64 run placed the marker at distance 80 and selected count 81. That value is an observation, not a required allocator layout. Automatic mode measures each invocation rather than reusing an offset from an earlier run.

The demonstration cap limits the attempted write length; it does not make any oversized write safe. Crossing the allocation boundary is undefined behavior. A write may corrupt unrelated data or allocator metadata, terminate the process, or appear to succeed. No corrupted marker, crash, or return value is guaranteed across platforms or builds.

## Cleanup and input validation

After a valid fill, both programs free both allocations. After an oversized fill, the vulnerable program flushes output and calls C11 `_Exit(0)` without freeing either allocation or running normal exit handlers, because the write may have damaged allocator metadata. Process teardown reclaims the memory. Standard output is configured as unbuffered before allocating the lab objects, reducing the need for stdio buffer allocation after corruption. Other runtime activity may still encounter damaged heap state. This is a teaching observation path, not a recovery technique.

Both versions parse decimal counts with `strtol`, reject values outside the platform's `long` range and negative values, and require exactly one data byte. Leading whitespace and an optional sign are accepted for numbers; trailing characters are rejected. Windows and Unix-like targets may have different `long` widths. A multibyte UTF-8 character is not a single byte, and command-line arguments cannot contain embedded NULs.

| Condition | Vulnerable version | Fixed version |
| --------- | ------------------ | ------------- |
| Wrong argument count | Usage on stderr; exit 2 | Same |
| Malformed, negative, or overflowing count; invalid byte | Parse error on stderr; exit 2 | Same |
| Numeric count 0–64 | Prints count, distance, buffer, and unchanged marker; frees allocations; exit 0 | Same |
| Numeric count 65–4096 | Out-of-bounds write; undefined behavior | Range error on stderr; exit 1 |
| Numeric count above 4096 within `long` range | Demonstration-limit error on stderr; exit 1 | Range error on stderr; exit 1 |
| `adjacent`, nearby forward layout | Attempts a write through the marker's first byte; undefined behavior | Range error on stderr; exit 1 |
| `adjacent`, unavailable layout | Layout error on stderr; exit 3 | Same |
| Allocation failure | Error on stderr; exit 3 | Same |

On the tested hardened Linux/glibc build, fortification detects a fill beyond the known 64-byte allocation and aborts before marker corruption. Windows has no glibc fortification. Stack canaries do not directly protect heap allocations, and ASLR/DEP do not replace the missing source-level bounds check. The fixed source provides that check.

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target all labs/heap/adjacent_data_overflow.c
./scripts/compile.sh --target all labs/heap/adjacent_data_overflow_fixed.c
```

The commands produce 24 binaries: two sources, six targets, and two profiles. Binaries and verified JSON reports are under `build/<target>/<profile>/adjacent_data_overflow[.exe]` and `adjacent_data_overflow_fixed[.exe]`. Supported targets are Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. macOS/BSD and Windows ARM are not compiler targets.

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

/out/$target/unprotected/adjacent_data_overflow 64 X
# Count: 64
# Forward distance: allocator-dependent
# Buffer: 64 X bytes
# Marker: 53 45 4e 54 49 4e 45 4c

/out/$target/unprotected/adjacent_data_overflow adjacent X
# On the observed native layout:
# Count: 81
# Forward distance: 80
# Buffer: 64 X bytes
# Marker: 58 45 4e 54 49 4e 45 4c
# Other layouts may report unavailable; the invalid write may also crash.

/out/$target/hardened/adjacent_data_overflow 65 X
# Tested Linux/glibc build: buffer overflow detected; aborts.

/out/$target/unprotected/adjacent_data_overflow_fixed 65 X
# Input too long: maximum is 64 bytes.
echo "$?"
# 1
```

## Automated verification

The test builds 24 binaries and verifies their compiler reports without compiler warnings. Native Linux checks cover argument errors, malformed and overflowing counts, byte validation, valid lengths through 64, the demonstration limit, and fixed rejection. Layout-aware checks use automatic mode: when available, the unprotected build must exhibit the intended first-byte marker corruption, the fixed build must reject the count, and the hardened Linux/glibc build must detect the overflow. Unavailable layouts are explicitly reported as skips rather than asserted to be adjacent.

Separate temporary AddressSanitizer builds verify heap-buffer-overflow writes at numeric counts 65, 66, and 128 and confirm that the fixed source stays in bounds. Numeric mode is used because ASan changes allocation layout; a marker-adjacency observation is not required for sanitizer detection. Temporary binaries are removed after testing. Windows and non-native CPUs receive build verification only.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_adjacent_data_overflow.py
```
