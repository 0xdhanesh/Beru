# Global/static buffer overflow

This lab demonstrates a string copy overflowing a buffer with static storage duration into an adjacent data field. The [vulnerable source](buffer_overflow.c) uses unchecked `strcpy`; the [fixed source](buffer_overflow_fixed.c) validates the input length before copying. Both are portable C11 and build for all six targets in the [Docker compiler](../../docker/compiler/README.md).

## The bug and correction

A file-scope `static` structure contains `char buffer[64]` followed by an eight-byte marker initialized to `SENTINEL`. This object has static storage duration, rather than living on the stack or heap. Using a structure gives the members a specified order; compile-time assertions verify the marker starts at offset 64 and the containing object occupies 72 bytes. The lab does not assume independently declared global variables will be adjacent.

The program accepts one command-line string. `strcpy(storage.buffer, input)` copies the string and its terminating NUL without checking capacity. Up to 63 input bytes fit. At 64 bytes, the terminator overwrites the first marker byte. Longer inputs also write data bytes into the marker. At 72 input bytes, the NUL is beyond the entire containing structure. Copying beyond the buffer member is already undefined behavior, even when the affected bytes belong to the following member.

This is an out-of-bounds write (CWE-787), caused by copying without checking destination capacity (CWE-120). The fixed version rejects `strlen(input) >= sizeof(storage.buffer)` and copies an accepted string with `memcpy`, including its NUL. It preserves accepted input without truncation. Counts are bytes; multibyte text can exceed the limit with fewer than 64 characters. Command-line strings cannot contain embedded NUL bytes.

Output reports the number of input bytes and prints exactly eight marker bytes in hexadecimal. Neither the marker nor an overflowed buffer is passed to a string-printing operation. Before corruption, the marker is `53 45 4e 54 49 4e 45 4c` (`SENTINEL`). This makes a NUL overwrite visible without introducing a second out-of-bounds string read.

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target all labs/global/buffer_overflow.c
./scripts/compile.sh --target all labs/global/buffer_overflow_fixed.c
```

These commands produce 24 binaries: two sources, six targets, and two profiles. The compiler supports Linux x86, x86_64, ARM hard-float, ARM64, and Windows x86/x86_64. Outputs and verified JSON reports are under `build/<target>/<profile>/buffer_overflow[.exe]` and `buffer_overflow_fixed[.exe]`. It does not target macOS/BSD or Windows ARM.

## Expected behavior

| Input | Vulnerable version | Fixed version |
| ----- | ------------------ | ------------- |
| Wrong argument count | Usage on stderr; exit 2 | Same |
| Empty string through 63 bytes | Prints byte count and unchanged marker; exit 0 | Same |
| 64 bytes or more | Out-of-bounds write; undefined behavior or a checked-copy abort | Range error on stderr; exit 1 |

The native Linux unprotected build is tested for the intended marker changes at lengths 64–71. For 64 `A` bytes, the expected marker is `00 45 4e 54 49 4e 45 4c`. For 65 `A` bytes, it is `41 00 4e 54 49 4e 45 4c`. No particular crash, output, or adjacent object corruption is guaranteed by C after the invalid write. Inputs beyond the containing structure can corrupt unrelated storage or terminate the program.

On the tested hardened Linux/glibc build, fortification detects the destination buffer's capacity and aborts at 64 bytes and above. Stack canaries do not directly protect this static object. Windows has no glibc fortification, and binary protections such as DEP and ASLR do not supply the missing bounds check. The fixed source is the correction; behavior under hardening depends on the platform and toolchain.

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

/out/$target/unprotected/buffer_overflow Beru
# Copied: 4 bytes
# Adjacent: 53 45 4e 54 49 4e 45 4c

input="$(python3 -c 'print("A" * 64)')"
/out/$target/unprotected/buffer_overflow "$input"
# Intended observation on the tested build:
# Copied: 64 bytes
# Adjacent: 00 45 4e 54 49 4e 45 4c

/out/$target/hardened/buffer_overflow "$input"
# Linux/glibc: buffer overflow detected; aborts.

/out/$target/unprotected/buffer_overflow_fixed "$input"
# Input too long: maximum is 63 bytes.
echo "$?"
# 1
```

## Automated verification

The test builds all 24 binaries and verifies their compiler reports without compiler warnings. Native Linux checks cover usage errors, empty input, byte-count boundaries, unprotected marker corruption at lengths 64–71, hardened fortification detection, and fixed rejection at 64 bytes and above. Windows and non-native CPUs receive build verification only.

Separate temporary AddressSanitizer builds confirm global-buffer-overflow writes at input lengths 72 and above, where the copy exceeds the whole global object. Ordinary ASan redzones surround the containing structure, not the boundary between its members: the 64–71-byte cases can corrupt the marker without a sanitizer report. The test checks those marker bytes directly and verifies the fixed source stays in bounds. Sanitizer binaries are removed after testing.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_global_buffer_overflow.py
```
