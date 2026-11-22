# Beru

Let the fun(c) begin...

Beru is a collection of planned, intentionally vulnerable C and C++ labs for learning secure coding and practicing reverse engineering. Each lab will isolate a memory safety issue or a related exploitation technique so its behavior can be compared across architectures and build profiles.

The repository contains this catalog, a [Docker-based C/C++ compiler](docker/compiler/README.md), and the [classic stack buffer overflow](labs/stack/classic_overflow.md), [stack off-by-one](labs/stack/off_by_one.md), [stack off-by-null](labs/stack/off_by_null.md), [stack buffer underflow](labs/stack/buffer_underflow.md), [stack out-of-bounds read](labs/stack/out_of_bounds_read.md), [Windows x86 SEH record overwrite](labs/windows/seh_overwrite.md), [global/static buffer overflow](labs/global/buffer_overflow.md), [global/static buffer underflow](labs/global/buffer_underflow.md), and [adjacent heap data overflow](labs/heap/adjacent_data_overflow.md) labs with bounds-checked corrections. Entries marked **Planned** have no implementation yet. The programs in `tests/fixtures/` are harmless compiler smoke tests. The catalog covers common families and representative variants, rather than every allocator-specific or platform-specific technique.

## Compile with Docker

Install Docker with a running Linux container engine, then run:

```bash
# Build the compiler image and produce both profiles for Linux x86_64.
./scripts/compile.sh tests/fixtures/hello.c

# Cross-compile both profiles for all six supported targets.
./scripts/compile.sh --target all tests/fixtures/hello.c

# Compile a C++ program for Windows x86_64 using only the hardened profile.
./scripts/compile.sh --target windows-x86_64 --profile hardened tests/fixtures/hello.cpp
```

Binaries and verified JSON build reports are written to `build/<target>/<profile>/` and ignored by Git. See the [compiler guide](docker/compiler/README.md) for the exact protections, custom sources, supported targets, limitations, and validation commands.

## Memory corruption catalog

“Windows / Unix-like” identifies the intended operating system families. Actual behavior depends on the architecture, ABI, compiler, allocator, and enabled mitigations. Reads and information leaks are included because they are relevant memory safety issues; they do not necessarily corrupt memory themselves.

| MEMORY CORRUPTION | Applicable OS | Source |
| ----------------- | ------------- | ------ |
| Classic stack buffer overflow — unchecked copy into a stack buffer | Windows / Unix-like | [Vulnerable source](labs/stack/classic_overflow.c), [fixed source](labs/stack/classic_overflow_fixed.c), [lab guide](labs/stack/classic_overflow.md) |
| Stack off-by-one overflow — one byte beyond a stack buffer | Windows / Unix-like | [Vulnerable source](labs/stack/off_by_one.c), [fixed source](labs/stack/off_by_one_fixed.c), [lab guide](labs/stack/off_by_one.md) |
| Stack off-by-null overflow — terminating NUL written beyond a stack buffer | Windows / Unix-like | [Vulnerable source](labs/stack/off_by_null.c), [fixed source](labs/stack/off_by_null_fixed.c), [lab guide](labs/stack/off_by_null.md) |
| Stack buffer underflow — write before the start of a stack buffer | Windows / Unix-like | [Vulnerable source](labs/stack/buffer_underflow.c), [fixed source](labs/stack/buffer_underflow_fixed.c), [lab guide](labs/stack/buffer_underflow.md) |
| Stack out-of-bounds read — access beyond a stack buffer | Windows / Unix-like | [Vulnerable source](labs/stack/out_of_bounds_read.c), [fixed source](labs/stack/out_of_bounds_read_fixed.c), [lab guide](labs/stack/out_of_bounds_read.md) |
| SEH record overwrite — corruption of a stack-based exception registration record | Windows x86; classic SEH chain layout | [Vulnerable source](labs/windows/seh_overwrite.c), [fixed source](labs/windows/seh_overwrite_fixed.c), [lab guide](labs/windows/seh_overwrite.md) |
| Global/static buffer overflow — overwrite adjacent static storage | Windows / Unix-like | [Vulnerable source](labs/global/buffer_overflow.c), [fixed source](labs/global/buffer_overflow_fixed.c), [lab guide](labs/global/buffer_overflow.md) |
| Global/static buffer underflow — write before static storage | Windows / Unix-like | [Vulnerable source](labs/global/buffer_underflow.c), [fixed source](labs/global/buffer_underflow_fixed.c), [lab guide](labs/global/buffer_underflow.md) |
| Heap overflow, variant 1 — overwrite data in an adjacent allocation | Windows / Unix-like; allocator layout dependent | [Vulnerable source](labs/heap/adjacent_data_overflow.c), [fixed source](labs/heap/adjacent_data_overflow_fixed.c), [lab guide](labs/heap/adjacent_data_overflow.md) |
| Heap overflow, variant 2 — overwrite an adjacent function pointer or object | Windows / Unix-like; allocator layout dependent | Planned: `labs/heap/adjacent_object_overflow.c` |
| Heap overflow, variant 3 — corrupt allocator metadata | Windows / Unix-like; allocator and version dependent | Planned: `labs/heap/metadata_overflow.c` |
| Heap off-by-one overflow — one byte beyond an allocation | Windows / Unix-like | Planned: `labs/heap/off_by_one.c` |
| Heap off-by-null overflow — terminating NUL beyond an allocation | Windows / Unix-like | Planned: `labs/heap/off_by_null.c` |
| Heap buffer underflow — write before an allocation | Windows / Unix-like | Planned: `labs/heap/buffer_underflow.c` |
| Heap out-of-bounds read — access beyond an allocation | Windows / Unix-like | Planned: `labs/heap/out_of_bounds_read.c` |
| Use after free (UAF) — access an allocation after releasing it | Windows / Unix-like | Planned: `labs/lifetime/use_after_free.c` |
| Dangling pointer — retain an alias to a freed object and subsequently dereference it | Windows / Unix-like | Planned: `labs/lifetime/dangling_pointer.c` |
| Use after realloc — access a stale alias after successful reallocation | Windows / Unix-like | Planned: `labs/lifetime/use_after_realloc.c` |
| Stack use after return — access an object after its function returns | Windows / Unix-like | Planned: `labs/lifetime/stack_use_after_return.c` |
| Stack use after scope — access an object after its block lifetime ends | Windows / Unix-like | Planned: `labs/lifetime/stack_use_after_scope.c` |
| Double free — release the same allocation twice | Windows / Unix-like | Planned: `labs/lifetime/double_free.c` |
| Invalid free — release a non-owned, interior, or non-heap pointer | Windows / Unix-like | Planned: `labs/lifetime/invalid_free.c` |
| Mismatched allocation/deallocation — mix incompatible allocation APIs | Windows / Unix-like; C++ runtime dependent | Planned: `labs/lifetime/mismatched_deallocation.cpp` |
| Uninitialized pointer use — dereference a pointer without a valid initialized value | Windows / Unix-like | Planned: `labs/pointers/uninitialized_pointer.c` |
| Null pointer dereference — read or write through a null pointer | Windows / Unix-like; typically a crash | Planned: `labs/pointers/null_dereference.c` |
| Uninitialized memory read — disclose or consume uninitialized data | Windows / Unix-like | Planned: `labs/disclosure/uninitialized_read.c` |
| Missing string terminator — read beyond an unterminated character buffer | Windows / Unix-like | Planned: `labs/disclosure/unterminated_string.c` |
| Integer overflow/underflow leading to an undersized allocation and out-of-bounds write | Windows / Unix-like; integer widths dependent | Planned: `labs/sizes/integer_wraparound.c` |
| Integer truncation leading to a buffer size mismatch | Windows / Unix-like; integer widths dependent | Planned: `labs/sizes/integer_truncation.c` |
| Signedness conversion leading to an invalid length | Windows / Unix-like | Planned: `labs/sizes/signedness_conversion.c` |
| Incorrect size calculation — confuse element counts and byte counts | Windows / Unix-like | Planned: `labs/sizes/incorrect_allocation_size.c` |
| Unchecked array index — out-of-bounds read or write | Windows / Unix-like | Planned: `labs/bounds/unchecked_index.c` |
| Incorrect pointer arithmetic — calculate an address outside its object | Windows / Unix-like | Planned: `labs/bounds/pointer_arithmetic.c` |
| Format string vulnerability — uncontrolled format permits disclosure or memory writes | Windows / Unix-like; runtime behavior dependent | Planned: `labs/format/uncontrolled_format.c` |
| Type confusion — interpret an object using an incompatible type or layout | Windows / Unix-like | Planned: `labs/objects/type_confusion.cpp` |
| C++ virtual table pointer corruption — overwrite an object's dispatch pointer | Windows / Unix-like; C++ ABI dependent | Planned: `labs/objects/vtable_corruption.cpp` |
| Memory lifetime race — concurrent access and release can cause UAF | Windows / Unix-like; threading runtime dependent | Planned: `labs/concurrency/lifetime_race.cpp` |

Buffer bounds terminology follows [MITRE CWE-119](https://cwe.mitre.org/data/definitions/119). Lifetime examples include [use after free (CWE-416)](https://cwe.mitre.org/data/definitions/416) and [double free (CWE-415)](https://cwe.mitre.org/data/definitions/415.html). A dangling pointer is a stale reference; dereferencing it can cause a use-after-free error, so those labs deliberately overlap.

## Related exploitation techniques

These are techniques that can build on a memory corruption vulnerability, rather than separate root-cause bug classes. Their feasibility depends on the specific target and mitigations.

| MEMORY CORRUPTION | Applicable OS | Source |
| ----------------- | ------------- | ------ |
| Return address overwrite — redirect a function's return after stack corruption | Windows / Unix-like; ABI dependent | Planned: `labs/control_flow/return_address.c` |
| Function pointer overwrite — redirect an indirect call through corrupted data | Windows / Unix-like | Planned: `labs/control_flow/function_pointer.c` |
| Return-to-library / return-to-libc — reuse existing library code | Windows / Unix-like; runtime and ABI dependent | Planned: `labs/code_reuse/return_to_library.c` |
| Return-oriented programming (ROP) — chain instruction sequences ending in returns | Windows / Unix-like; architecture and mitigation dependent | Planned: `labs/code_reuse/rop.c` |
| Jump-oriented programming (JOP) — chain instruction sequences using indirect jumps | Windows / Unix-like; architecture and mitigation dependent | Planned: `labs/code_reuse/jop.c` |
| Call-oriented programming (COP) — reuse code through indirect call sequences | Windows / Unix-like; architecture and mitigation dependent | Planned: `labs/code_reuse/cop.c` |
| Stack pivoting — redirect the stack pointer to controlled storage | Windows / Unix-like; architecture and mitigation dependent | Planned: `labs/control_flow/stack_pivot.c` |
| Data-only corruption — alter program decisions without redirecting control flow | Windows / Unix-like | Planned: `labs/control_flow/data_only.c` |

Microsoft's [exploit protection reference](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference) describes defenses relevant to these labs, including DEP, ASLR, SEHOP, and ROP mitigations.

## Planned build matrix

Each supported lab is intended to have two profiles for each applicable target: **stripped with binary protections** and **unstripped without optional binary protections**. The compiler currently supports Linux x86, x86_64, ARM hard-float, and ARM64, plus Windows x86 and x86_64. The broader Unix-like and Windows ARM targets below remain planned.

| Architecture | Planned OS targets | Planned profiles |
| ------------ | ------------------ | ---------------- |
| x86 (32-bit) | Windows / Unix-like | Stripped + protected; unstripped + unprotected |
| x86_64 (64-bit) | Windows / Unix-like | Stripped + protected; unstripped + unprotected |
| ARM (32-bit) | Unix-like initially; Windows subject to toolchain/runtime availability | Stripped + protected; unstripped + unprotected |
| AArch64 / ARM64 (64-bit) | Windows / Unix-like | Stripped + protected; unstripped + unprotected |

The protected profile will enable the hardening supported by its toolchain and platform, such as stack canaries, NX/DEP, PIE/ASLR support, ELF RELRO, and applicable control-flow protections. The unprotected profile will disable optional build-time hardening where supported; operating system and hardware policies may still enforce protections. Symbol stripping is independent of hardening, and Windows debug symbols may live in separate PDB files.

Platform-specific labs, such as classic x86 SEH overwrites, will be built only for compatible targets. Allocator-specific labs will document the required allocator and version when implemented. Each future lab should include its vulnerable source, secure correction, build instructions, expected behavior, and verification of the resulting binary's symbols and protections.
