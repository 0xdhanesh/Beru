# Docker compiler

`scripts/compile.sh` compiles repository C/C++ programs inside a Debian Bookworm container. It builds **both profiles by default**, verifies the resulting binaries, and produces a JSON report for each output. No generated program is executed during compilation or verification.

## Requirements and usage

Use Bash and a running Docker Linux engine on Linux, macOS, or Windows through WSL2. GCC, Python, and the cross-compilers are installed in the image; no host compiler is required. The image builds for the Docker engine's native architecture (AMD64 or ARM64). The first build downloads Debian packages and requires network access; compilation itself runs without networking.

Run from any working directory using the script's path. Source and include paths are always relative to this repository, and must resolve to files or directories within it.

```bash
./scripts/compile.sh tests/fixtures/hello.c
./scripts/compile.sh --target all tests/fixtures/hello.c
./scripts/compile.sh --target linux-arm64 --profile unprotected tests/fixtures/hello.c
./scripts/compile.sh --target windows-x86 --profile hardened tests/fixtures/hello.cpp

# Multiple translation units, include paths, preprocessor definitions, and libraries.
./scripts/compile.sh --name mixed --include tests/fixtures --define DEMO=1 \
  --pthread tests/fixtures/mixed.cpp tests/fixtures/helper.c
./scripts/compile.sh --library m tests/fixtures/hello.c
```

Supported options:

| Option | Default | Meaning |
| ------ | ------- | ------- |
| `--target` | `linux-x86_64` | One target from the table below, or `all` |
| `--profile` | `both` | `unprotected`, `hardened`, or `both` |
| `--name` | First source filename without its suffix | Output basename; Windows gets an additional `.exe` suffix |
| `--include` | None | Repository include directory; repeatable |
| `--define` | None | Macro name or `NAME=VALUE`; repeatable |
| `--library` | None | Library name such as `m`; repeatable; linked after objects |
| `--pthread` | Off | Enable thread compilation and linking |

C sources use C11 and C++ sources use C++17. Mixed builds compile each source with its own language driver and link with G++ when needed. A failed compilation or verification exits nonzero; successfully verified outputs from earlier targets remain available. Existing binaries are replaced only after their replacement passes verification. Builds with the same target, profile, and output name should be run sequentially.

## Targets

| Target | Binary format | Compiler prefix |
| ------ | ------------- | --------------- |
| `linux-x86` | 32-bit x86 ELF | `i686-linux-gnu` |
| `linux-x86_64` | 64-bit x86 ELF | `x86_64-linux-gnu` |
| `linux-arm` | 32-bit ARM hard-float ELF | `arm-linux-gnueabihf` |
| `linux-arm64` | AArch64 ELF | `aarch64-linux-gnu` |
| `windows-x86` | 32-bit x86 PE | `i686-w64-mingw32` |
| `windows-x86_64` | 64-bit x86 PE | `x86_64-w64-mingw32` |

Linux outputs use glibc, not macOS, BSD, or Android runtimes. Windows uses MinGW-w64 with POSIX thread support; GCC support libraries are linked statically, while Windows system DLL dependencies remain. Windows ARM/ARM64 and MSVC-specific protections are not supported by this image. Platform-specific lab sources must be compiled only for compatible targets.

## Profiles and verification

“Unprotected” disables the optional binary protections listed here. “Hardened” enables the documented set supported by these toolchains; there is no portable switch that guarantees every possible protection.

| Feature | `unprotected` | `hardened` |
| ------- | ------------- | ---------- |
| Optimization | `-O0` | `-O2` |
| Debug data and symbols | `-g3`, retained | Removed with target `strip --strip-all` |
| Stack canaries | `-fno-stack-protector` | `-fstack-protector-all` |
| Automatic local variable initialization | Uninitialized | Zero initialization |
| libstdc++ assertions | Macro undefined | `_GLIBCXX_ASSERTIONS` enabled |
| Linux fortified libc calls | `_FORTIFY_SOURCE` undefined | `_FORTIFY_SOURCE=3` |
| Linux position-independent executable | Disabled | PIE enabled |
| Linux stack execution | Executable stack requested | Non-executable stack requested |
| Linux RELRO / immediate binding | No RELRO, lazy binding | Full RELRO, immediate binding |
| Linux stack clash protection | Disabled | Enabled where GCC supports it for the target |
| Linux separate code segments | Toolchain default | Explicitly enabled |
| Linux x86/x86_64 CET instrumentation | Disabled | `-fcf-protection=full` |
| Linux ARM64 branch protection | Disabled | `-mbranch-protection=standard` (PAC/BTI instrumentation) |
| Windows ASLR / DEP compatibility | Disabled | Enabled, with relocations |
| Windows x86_64 high entropy ASLR | Disabled | Enabled |

The flags follow the [GCC instrumentation documentation](https://gcc.gnu.org/onlinedocs/gcc-12.5.0/gcc/Instrumentation-Options.html) and [GNU linker options](https://sourceware.org/binutils/docs/ld/Options.html). The script verifies ELF PIE, GNU_STACK permissions, RELRO, immediate binding, stack canary references, symbol tables, and debug data. For PE it verifies ASLR, DEP, high entropy ASLR (64-bit), canary references before stripping, and symbol/debug removal. Failed checks stop the build.

Reports at `build/<target>/<profile>/<name>[.exe].json` include compiler version, commands, flags, source hashes, binary hash, pre-strip properties, and final binary properties. Canary references are checked before stripping because static MinGW canary symbols are removed by stripping; their final report value is `null` (unobservable), while ELF dynamic imports remain observable. Reports verify the listed binary properties; they do not prove every function or dependency is protected. Fortify and C++ assertions apply only where source operations and libraries support them. CET, PAC, and BTI enforcement depends on compatible startup objects, libraries, hardware, and operating system support; instrumented source alone does not establish process-wide enforcement. ARM32 GCC stack clash coverage is target dependent. This image does not provide Windows CFG, SafeSEH, MSVC `/GS`, or sanitizers.

Build flags do not disable host ASLR or mandatory operating system/hardware policies. An unprotected binary can still encounter runtime protections. Hardening and optimization can change or remove undefined behavior in intentionally vulnerable labs.

## Docker and output configuration

```bash
# Reuse the image after an initial build; omit this variable after editing compiler files.
BERU_SKIP_IMAGE_BUILD=1 ./scripts/compile.sh tests/fixtures/hello.c

# Change the host output directory or image tag.
BERU_OUTPUT_DIR=/tmp/beru-build ./scripts/compile.sh tests/fixtures/hello.c
BERU_COMPILER_IMAGE=beru-compiler:dev ./scripts/compile.sh tests/fixtures/hello.c
```

`BERU_OUTPUT_DIR` defaults to `<repo>/build`; relative values are resolved against the repository root. Image builds are cached. Debian package updates may change future compiler image builds; reports capture compiler versions and binary hashes, but builds are not claimed to be bit-for-bit reproducible. Keep the built image by digest when an exercise requires a fixed toolchain.

The container runs as the invoking user's UID/GID with no network or Linux capabilities, a read-only root filesystem, read-only sources, writable output, and temporary compiler space. It does not need privileged mode or changes to host kernel settings. Docker bind mount paths containing commas are unsupported by this launcher.

## Smoke verification

The smoke test builds harmless C, C++, and mixed-language fixtures for all six targets and both profiles: **36 binaries**. It checks architecture identifiers, profile verification, symbol/debug retention, report hashes, failure behavior, and input validation. It does not execute cross-compiled programs or claim runtime coverage on Windows.

```bash
docker build -t beru-compiler:local docker/compiler
mkdir -p build
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$PWD/build,target=/out" \
  --entrypoint python3 beru-compiler:local /src/tests/smoke_compile.py
```
