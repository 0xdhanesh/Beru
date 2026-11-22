# Windows x86 SEH record overwrite

This lab corrupts a real stack-based exception registration record on **32-bit Windows x86**. The [vulnerable source](seh_overwrite.c) copies raw input bytes beyond a 64-byte buffer into an adjacent record. The [fixed source](seh_overwrite_fixed.c) checks the buffer capacity first. Both use the repository's MinGW-w64 GCC toolchain and C11. Other compiler targets are rejected at compile time.

## Record layout and bug

Classic x86 SEH uses a linked list of stack records containing a `Next` pointer followed by a `Handler` pointer. Microsoft describes this layout and how overwrites affect exception dispatch in its [SEHOP explanation](https://www.microsoft.com/en-us/msrc/blog/2009/02/preventing-the-exploitation-of-structured-exception-handler-seh-overwrites-with-sehop/). MinGW-w64's own [x86 thread implementation](https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-libraries/winpthreads/src/thread.c) registers stack records using `__readfsdword(0)` and `__writefsdword(0)`.

The lab explicitly places the buffer and Windows `EXCEPTION_REGISTRATION_RECORD` inside one stack-local structure. Compile-time assertions verify the following layout, rather than assuming the compiler will place unrelated local variables next to each other:

| Offset from buffer start | Size | Contents |
| ------------------------ | ---- | -------- |
| 0–63 | 64 bytes | Raw byte buffer |
| 64–67 | 4 bytes | Registration record's `Next` pointer |
| 68–71 | 4 bytes | Registration record's `Handler` pointer |

The record starts with the original chain head and a handler returning `ExceptionContinueSearch`. The program links this record at `FS:[0]`, then performs the copy while the record is live. A separate, non-inlined copy routine uses volatile byte stores to keep the teaching operation visible under optimization.

The vulnerable length check permits up to 72 bytes, the size of the containing structure. That demonstration limit confines the intended overwrite to the buffer and record, but it does **not** enforce the destination array's boundary. Lengths 65–68 overwrite part or all of `Next`; lengths 69–72 also overwrite `Handler`. Crossing the array boundary is undefined behavior in C even though another member occupies the following bytes. This is a stack buffer overflow (CWE-121) caused by an unchecked copy relative to the destination buffer (CWE-120).

The original chain head is saved separately. After copying, the program restores `FS:[0]` from that saved value, never from the overwritten `Next`. It then checks restoration and compares the record's byte representations with a saved snapshot. It does not evaluate the corrupted pointer values, print addresses, raise an exception, or call the overwritten handler. Output reports whether each field changed. A partial overwrite can coincidentally preserve a field's original byte value.

This demonstrates registration-record corruption, not exception-dispatch redirection. There are no calls to C library output routines during the deliberately corrupted interval. An exception during that interval could still encounter the damaged chain. Undefined behavior means no result is guaranteed across arbitrary toolchains or environments.

## Correction and input contract

The fixed version rejects lengths greater than `sizeof(frame.buffer)` **before** linking the record or copying input. The copy transfers exactly `strlen(INPUT)` bytes without a terminating NUL; therefore all 64 buffer bytes are usable. The program never prints the buffer as a string. Command-line arguments cannot contain embedded NULs, and lengths count bytes rather than Unicode characters.

Both programs accept exactly one argument, `INPUT`. Wrong argument counts print usage and exit 2. Oversized input prints an error and exits 1. Successful observation prints three lines and exits 0. A failed chain-restoration check reports an error and exits 3.

| Input length | Vulnerable version | Fixed version |
| ------------ | ------------------ | ------------- |
| 0–64 | Both record fields unchanged | Same |
| 65–68 | Overwrites `Next`; `Handler` untouched | Rejects; maximum 64 bytes |
| 69–72 | Overwrites both record fields | Rejects; maximum 64 bytes |
| 73 or more | Rejects; demonstration maximum 72 bytes | Rejects; maximum 64 bytes |

## Build both profiles

From the repository root:

```bash
./scripts/compile.sh --target windows-x86 labs/windows/seh_overwrite.c
./scripts/compile.sh --target windows-x86 labs/windows/seh_overwrite_fixed.c
```

These commands produce four binaries and verified JSON reports under `build/windows-x86/{unprotected,hardened}/`. The unprotected binaries retain symbols and debug information; hardened binaries are stripped and built with the compiler's stack-protector, ASLR, and DEP flags. See the [compiler guide](../../docker/compiler/README.md) for profile details. Do not use `--target all`: this lab deliberately rejects Unix-like, Windows x64, and ARM targets. A 32-bit executable may run under an x86-compatible Windows installation's WoW64 support; this does not turn it into an x64 SEH example.

Binary hardening does not repair this source-level overflow. The intended overwrite affects a member inside the frame rather than necessarily reaching a compiler canary. This compiler's build reports do not verify SafeSEH or runtime SEHOP policy. Microsoft's [exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference#validate-exception-chains-sehop) describes SEHOP validation during exception dispatch; this lab restores the chain without dispatching, so its output cannot establish whether SEHOP would block exploitation. No mitigation changes are required to observe the record bytes.

## Run on Windows

Copy the built executables into an isolated Windows lab environment with x86 execution support. From PowerShell in the repository root:

```powershell
& .\build\windows-x86\unprotected\seh_overwrite.exe ('A' * 64)
# Copied: 64 bytes
# Next: unchanged
# Handler: unchanged

& .\build\windows-x86\unprotected\seh_overwrite.exe ('A' * 72)
# Intended observation, subject to undefined behavior:
# Copied: 72 bytes
# Next: changed
# Handler: changed

& .\build\windows-x86\hardened\seh_overwrite_fixed.exe ('A' * 72)
# Input too long: maximum is 64 bytes.
$LASTEXITCODE
# 1
```

## Automated verification

Build verification runs in the compiler container and checks four PE binaries and their profile reports, rejects compiler warnings, and confirms both sources reject all five unsupported targets:

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/test_seh_overwrite.py
```

The container has no Windows runtime, so it explicitly skips execution. On Windows with Python and the built executables, run:

```powershell
py tests/test_seh_overwrite.py --runtime-only --build-dir build
```

Runtime checks cover argument counts, empty input, lengths through the 64-byte boundary, vulnerable lengths 65–72, the demonstration cap, fixed rejection, and successful chain restoration in both profiles. Two fill bytes avoid assuming a particular pointer byte during partial overwrites. These are checks of the intended teaching behavior; they do not make the vulnerable copy defined C behavior. AddressSanitizer is not used: the overwrite stays inside the containing structure, so ordinary stack redzones would not reliably detect it.
