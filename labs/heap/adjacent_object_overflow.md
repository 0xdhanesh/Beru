# Heap overflow: adjacent object callback

The [vulnerable source](adjacent_object_overflow.c) copies beyond a 64-byte heap buffer into a separately allocated object containing a function pointer. On a suitable allocator layout, the overwrite changes which built-in callback an indirect call invokes. The [fixed source](adjacent_object_overflow_fixed.c) checks the destination capacity before copying. Both sources are C11 and build for the six targets in the [Docker compiler](../../docker/compiler/README.md).

## Bug and correction

The program allocates a buffer with `malloc(64)` and an object with `malloc(sizeof(*object))`. The object's first member is a `void (*)(void)` callback, initially set to `original_callback`. These are separate allocations; the object is not embedded after the buffer in a single allocation.

The vulnerable operation is `memcpy(buffer, payload, count)`. The source payload has 4096 bytes, but the destination has only 64. The vulnerable program checks the demonstration limit without enforcing the destination's capacity. Counts 0–64 are valid raw-byte copies, with no string terminator; every larger copy is undefined behavior (CWE-122 / CWE-787). The fixed version rejects counts above 64 before the copy, including the count selected by automatic mode.

The interface is `COUNT|adjacent`:

- A decimal `COUNT` copies that many `X` bytes. The vulnerable source permits 0–4096; the fixed source permits 0–64. A numeric overflow need not reach the callback to be invalid.
- `adjacent` measures the allocations in this process. If the object is at least 64 bytes after the buffer and the entire callback representation fits within the 4096-byte demonstration range, it selects `count = distance + sizeof(callback_fn)`. The local payload contains `X` bytes followed, at that measured offset, by the representation of `replacement_callback`. The unchecked copy then attempts to replace the object's callback. An unsuitable layout is reported without copying.

The replacement is a second built-in function that only prints `Callback: replacement`. Its address is obtained from a real function pointer in the same process and copied as bytes; there are no guessed code addresses, integer-to-function-pointer casts, external code, or embedded NUL command-line arguments. This demonstrates a control-flow consequence of object corruption.

Before reading the possibly corrupted callback as a function pointer, the program compares its object representation with the saved original and replacement representations using `memcmp`. It invokes `object->callback()` only for a recognized representation. Otherwise it prints `Callback: unrecognized bytes; call skipped`. This guard limits the intended observation to the two built-in callbacks; it does not make the preceding out-of-bounds write defined or safe. The actual fix is the capacity check.

## Allocator and platform limits

Consecutive allocations do not guarantee forward placement, adjacency, a fixed gap, or a clear path between objects. Allocator metadata, padding, arenas, instrumentation, and unrelated allocations can affect the layout. The program observes `uintptr_t` address representations rather than subtracting unrelated pointers, assuming the flat-address Windows and Linux targets supported here. The check establishes only a nearby forward object, not that intervening bytes can be overwritten safely.

The native Linux ARM64 unprotected test observed a distance of 80 and an 8-byte callback. Automatic mode selected 88 bytes and printed `Callback: replacement`. These are observations, not portable constants. Each invocation measures its own layout. Other builds may report layout unavailable, crash, or behave differently because any oversized write is undefined behavior. The demonstration limit is not a safety boundary.

The tested hardened Linux/glibc build aborted with `buffer overflow detected` before dispatch, because fortification knew the destination's size. Windows does not provide glibc fortification. Stack canaries do not directly protect the heap; ASLR and DEP do not supply the missing bounds check. Hardening and optimization may change the manifestation of undefined behavior. macOS/BSD and Windows ARM are not compiler targets in this repository.

Standard output is configured as unbuffered before the heap allocations. Valid copies free both allocations. After an oversized copy the vulnerable source flushes output and calls `_Exit(0)`, skipping frees and normal exit handlers because allocator metadata may be damaged. Process teardown reclaims memory. Runtime activity may still encounter corrupted heap state; this is an observation path, not a recovery mechanism.

## Input and exit behavior

Both sources parse counts with `strtol`, rejecting negative values, trailing characters, and values outside the platform's `long` range. Leading whitespace and an optional sign are accepted; `long` widths differ across targets.

| Condition | Vulnerable source | Fixed source |
| --------- | ----------------- | ------------ |
| Wrong argument count | Usage; exit 2 | Same |
| Malformed, negative, or overflowing count | Parse error; exit 2 | Same |
| Numeric count 0–64 | Original callback; exit 0 | Same |
| Numeric count 65–4096 | Out-of-bounds copy; undefined behavior | Capacity error; exit 1 |
| Numeric count above 4096 within `long` range | Demonstration-limit error; exit 1 | Capacity error; exit 1 |
| `adjacent`, suitable layout | Attempts callback replacement; undefined behavior | Capacity error; exit 1 |
| `adjacent`, unsuitable layout | Layout error; exit 3 | Same |
| Allocation failure | Allocation error; exit 3 | Same |

Successful observation prints the count, forward distance (or `unavailable`), callback representation size, and callback result. Errors go to stderr. An observed oversized copy may exit 0 through `_Exit`; this does not indicate memory safety.

## Build and run

From the repository root:

```bash
./scripts/compile.sh --target all labs/heap/adjacent_object_overflow.c
./scripts/compile.sh --target all labs/heap/adjacent_object_overflow_fixed.c
```

These commands produce 24 binaries and verified JSON reports under `build/<target>/<profile>/`. Targets are Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64, with unprotected and hardened profiles.

Start an isolated shell with the binaries mounted read-only:

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

/out/$target/unprotected/adjacent_object_overflow 64
# Callback: original (after the count/distance/size lines)

/out/$target/unprotected/adjacent_object_overflow adjacent
# Observed Linux ARM64 output:
# Count: 88
# Forward distance: 80
# Callback bytes: 8
# Callback: replacement
# Other layouts may be unavailable or the invalid write may crash.

/out/$target/hardened/adjacent_object_overflow adjacent
# Tested Linux/glibc: buffer overflow detected; aborts.

/out/$target/unprotected/adjacent_object_overflow_fixed adjacent
# Suitable layout: Input too long: maximum is 64 bytes. (exit 1)
# Unsuitable layout: layout error (exit 3)
```

## Automated verification

The [test](../../tests/test_adjacent_object_overflow.py) cross-builds both sources for all six targets and both profiles, rejects compiler warnings, and checks each binary report. Native Linux checks cover usage, malformed and overflowing counts, valid copy boundaries, demonstration limits, and fixed rejection. Automatic mode verifies callback replacement in the unprotected build, rejection in the fixed build, and fortification detection in the hardened Linux/glibc build when the layout is available. Unavailable layouts are explicitly reported as skips.

Temporary AddressSanitizer builds detect heap-buffer-overflow writes for counts 65, 66, and 128 and verify that the fixed source rejects them. They use numeric mode because instrumentation changes allocation layout. Windows and non-native CPUs receive compilation and binary verification only, not runtime testing.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_adjacent_object_overflow.py
```
