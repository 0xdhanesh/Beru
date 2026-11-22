# Stack off-by-one overflow

This lab demonstrates a capacity check that is one byte too permissive. The [vulnerable source](off_by_one.c) accepts up to **65 data bytes** for a **64-byte stack buffer**, then copies them with `memcpy`. The [fixed source](off_by_one_fixed.c) accepts at most 64 bytes. Both are portable C11 and use the repository's [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

The vulnerable guard is:

```c
if (length > sizeof(buffer) + 1) {
    /* Reject the input. */
}
```

The extra `+ 1` makes the maximum accepted length 65. At that length, `memcpy(buffer, input, length)` writes 64 bytes inside `buffer[0..63]` and one data byte outside it. Lengths of 66 bytes and above are rejected before copying, so this example isolates a single-byte overflow rather than an unrestricted copy. This is an [off-by-one error (CWE-193)](https://cwe.mitre.org/data/definitions/193.html) leading to a [stack-based buffer overflow (CWE-121)](https://cwe.mitre.org/data/definitions/121.html).

The correction removes `+ 1` from the capacity check. The buffer holds raw bytes, not a NUL-terminated string: the program deliberately does not copy the terminator, and prints using `fwrite` with an explicit byte count. Thus 64 input bytes fit. The overflow byte at length 65 is an input data byte, which distinguishes this lab from the [off-by-null lab](off_by_null.md). Lengths count bytes, not Unicode characters; command-line strings cannot contain embedded NULs.

The vulnerable version limits its output to 64 bytes to avoid introducing an additional out-of-bounds read after the faulty write. Undefined behavior has already occurred at the write, so even that output is not guaranteed.

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target all labs/stack/off_by_one.c
./scripts/compile.sh --target all labs/stack/off_by_one_fixed.c
```

Each source produces both `unprotected` and `hardened` binaries for Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. Outputs and verified JSON reports are under `build/<target>/<profile>/off_by_one[.exe]` and `off_by_one_fixed[.exe]`. This compiler does not target macOS/BSD or Windows ARM.

## Expected behavior

| Input length | Vulnerable version | Fixed version |
| ------------ | ------------------ | ------------- |
| Missing argument or multiple arguments | Usage on stderr; exit 2 | Usage on stderr; exit 2 |
| 0–64 bytes | Prints `Copied: <input>`; exit 0 | Prints `Copied: <input>`; exit 0 |
| 65 bytes | One-byte stack overwrite in the unchecked source; hardened Linux/glibc build detects it | Error on stderr; exit 1 |
| 66 bytes or more | Error on stderr; exit 1 | Error on stderr; exit 1 |

The vulnerable rejection message reports its erroneous maximum of 65 bytes. The fixed version reports the correct maximum of 64 bytes.

Linux/glibc fortification checks the `memcpy` destination size in the hardened build and aborts at 65 bytes. An unprotected build can appear to succeed, crash, or corrupt neighboring data. A single-byte overwrite can land in padding and escape stack-canary detection; a crash or an altered return address is not guaranteed. Windows does not use glibc fortification, and its detection behavior depends on layout and canaries. Hardening does not correct the faulty bound.

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

fits="$(python3 -c 'print("A" * 64)')"
overflow="$(python3 -c 'print("A" * 65)')"
/out/$target/unprotected/off_by_one "$fits"
# Prints all 64 data bytes successfully.
/out/$target/unprotected/off_by_one "$overflow"
# Undefined behavior; may appear to work despite the invalid write.
/out/$target/hardened/off_by_one "$overflow"
# Linux/glibc: buffer overflow detected; aborts.
/out/$target/unprotected/off_by_one_fixed "$overflow"
# Input too long: maximum is 64 bytes.
echo "$?"
# 1
```

## Automated verification

The test builds 24 binaries (two sources, six targets, two profiles) and verifies the compiler reports. Native Linux runtime checks cover argument errors, empty input, 63/64-byte accepted boundaries, 65-byte fixed rejection, larger rejected inputs, and hardened overflow detection. A separate temporary AddressSanitizer build confirms the 65-byte write crosses the stack buffer boundary and that the fixed source stays in bounds at the tested lengths. Sanitizer builds supplement the standard profiles; their binaries are removed after testing. Windows and non-native CPUs receive build verification only.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_off_by_one.py
```
