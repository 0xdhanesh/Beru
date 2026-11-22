# Stack off-by-null overflow

This lab demonstrates a length check that forgets to reserve space for a string's terminating NUL. The [vulnerable source](off_by_null.c) accepts up to 64 data bytes for a 64-byte stack buffer, then copies the string including its terminator. The [fixed source](off_by_null_fixed.c) accepts at most 63 data bytes. Both are portable C11 and use the repository's [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

The vulnerable check rejects only `length > sizeof(buffer)`. At exactly 64 data bytes, `memcpy(buffer, input, length + 1)` copies the data into `buffer[0..63]` and writes the terminating NUL at `buffer[64]`, one byte past the array. Larger inputs are rejected before copying, isolating the NUL-only overflow. Unlike the [off-by-one lab](off_by_one.md), the byte written outside the buffer is always zero, rather than an input data byte.

The fixed check uses `length >= sizeof(buffer)`, reserving one byte for the terminator and rejecting oversized input without truncation. Lengths count bytes, not Unicode characters; command-line strings cannot contain embedded NULs. Both versions print with `fwrite` and the input data length so the example does not add an out-of-bounds string read. Undefined behavior has already occurred at the vulnerable write, so subsequent output is not guaranteed.

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target all labs/stack/off_by_null.c
./scripts/compile.sh --target all labs/stack/off_by_null_fixed.c
```

Each source produces both `unprotected` and `hardened` binaries for Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. Outputs and verified JSON reports are under `build/<target>/<profile>/off_by_null[.exe]` and `off_by_null_fixed[.exe]`. This compiler does not target macOS/BSD or Windows ARM.

## Expected behavior

| Input length | Vulnerable version | Fixed version |
| ------------ | ------------------ | ------------- |
| Missing argument or multiple arguments | Usage on stderr; exit 2 | Usage on stderr; exit 2 |
| 0–63 bytes | Prints `Copied: <input>`; exit 0 | Prints `Copied: <input>`; exit 0 |
| 64 bytes | Writes the terminating NUL beyond the stack buffer; hardened Linux/glibc build detects it | Error on stderr; exit 1 |
| 65 bytes or more | Error on stderr; exit 1 | Error on stderr; exit 1 |

The vulnerable rejection message reports its erroneous maximum of 64 bytes. The fixed version reports the correct maximum of 63 bytes.

Linux/glibc fortification checks the `memcpy` destination size in the hardened build and aborts when the requested copy is 65 bytes. An unprotected build can appear to succeed, crash, or corrupt neighboring data. A zero byte can land in padding or overwrite a byte that was already zero, including a canary byte on some platforms, so stack-canary detection is not guaranteed. Windows does not use glibc fortification; its detection behavior depends on layout and canaries. Hardening does not correct the faulty bound. No particular stack layout, crash, or return-address overwrite is assumed.

## Run in Docker

Start a shell with the built binaries mounted read-only:

```bash
docker run --rm -it --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD/build,target=/out,readonly" \
  --entrypoint /bin/bash beru-compiler:local
```

Inside the container, choose the native Linux target and compare inputs:

```bash
case "$(uname -m)" in
  aarch64) target=linux-arm64 ;;
  x86_64) target=linux-x86_64 ;;
esac

fits="$(python3 -c 'print("A" * 63)')"
overflow="$(python3 -c 'print("A" * 64)')"
/out/$target/unprotected/off_by_null "$fits"
# Prints all 63 data bytes successfully.
/out/$target/unprotected/off_by_null "$overflow"
# Undefined behavior; may appear to work despite the NUL overwrite.
/out/$target/hardened/off_by_null "$overflow"
# Linux/glibc: buffer overflow detected; aborts.
/out/$target/unprotected/off_by_null_fixed "$overflow"
# Input too long: maximum is 63 bytes.
echo "$?"
# 1
```

## Automated verification

The test builds 24 binaries (two sources, six targets, two profiles) and verifies their compiler reports. Native Linux runtime checks cover argument errors, empty input, accepted boundaries through 63 bytes, fixed rejection at 64 bytes, larger rejected inputs, and hardened overflow detection. A separate temporary AddressSanitizer build confirms that copying 64 data bytes plus their NUL crosses the stack buffer boundary, while the fixed source stays in bounds at the tested lengths. Sanitizer binaries are removed after testing. Windows and non-native CPUs receive build verification only.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_off_by_null.py
```
