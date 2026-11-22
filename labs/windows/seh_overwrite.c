/*
 * Intentionally vulnerable learning lab: CWE-121 / CWE-120.
 * Windows x86 / MinGW-w64 only; see seh_overwrite.md.
 */
#if !defined(_WIN32) || !defined(__i386__)
#error "This lab requires Windows x86 (32-bit) and the MinGW-w64 GCC toolchain."
#else
#include <windows.h>
#include <intrin.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

struct lab_frame {
    unsigned char buffer[64];
    EXCEPTION_REGISTRATION_RECORD registration;
};

_Static_assert(sizeof(void *) == 4, "Classic x86 SEH requires 32-bit pointers");
_Static_assert(offsetof(struct lab_frame, registration) == 64, "Unexpected record offset");
_Static_assert(offsetof(EXCEPTION_REGISTRATION_RECORD, Next) == 0, "Unexpected Next offset");
_Static_assert(offsetof(EXCEPTION_REGISTRATION_RECORD, Handler) == 4, "Unexpected Handler offset");
_Static_assert(sizeof(EXCEPTION_REGISTRATION_RECORD) == 8, "Unexpected SEH record size");
_Static_assert(sizeof(struct lab_frame) == 72, "Unexpected frame padding");

static EXCEPTION_DISPOSITION NTAPI continue_search(
    struct _EXCEPTION_RECORD *exception, void *frame,
    struct _CONTEXT *context, void *dispatcher) {
    (void)exception;
    (void)frame;
    (void)context;
    (void)dispatcher;
    return ExceptionContinueSearch;
}

/* Separate, volatile stores keep the teaching copy visible in both profiles. */
static __attribute__((noinline)) void copy_bytes(
    volatile unsigned char *destination, const char *source, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        destination[i] = (unsigned char)source[i];
    }
}

static int copy_input(const char *input) {
    struct lab_frame frame;
    unsigned char before[sizeof(frame.registration)];
    unsigned char after[sizeof(frame.registration)];
    const size_t length = strlen(input);
    const DWORD original_head = __readfsdword(0);

    /* Limit the demonstration to the buffer and adjacent registration record.
     * This harness limit does NOT enforce the buffer's 64-byte boundary. */
    if (length > sizeof(frame)) {
        fputs("Input too long: demonstration maximum is 72 bytes.\n", stderr);
        return 1;
    }

    memset(frame.buffer, '.', sizeof(frame.buffer));
    frame.registration.Next = (EXCEPTION_REGISTRATION_RECORD *)original_head;
    frame.registration.Handler = continue_search;
    memcpy(before, &frame.registration, sizeof(before));

    /* Register a real stack record; preserve the old head outside the record. */
    __asm__ __volatile__("" ::: "memory");
    __writefsdword(0, (DWORD)&frame.registration);
    __asm__ __volatile__("" ::: "memory");

    /* Deliberate bug: 65-72 bytes overflow buffer into the live SEH record. */
    copy_bytes(frame.buffer, input, length);

    /* Never follow the corrupted Next or invoke the overwritten Handler. */
    __asm__ __volatile__("" ::: "memory");
    __writefsdword(0, original_head);
    __asm__ __volatile__("" ::: "memory");
    memcpy(after, &frame.registration, sizeof(after));
    if (__readfsdword(0) != original_head) {
        fputs("SEH chain restoration failed.\n", stderr);
        return 3;
    }

    /* Compare representations, without evaluating corrupted pointer values. */
    printf("Copied: %zu bytes\n", length);
    printf("Next: %s\n", memcmp(before, after, 4) ? "changed" : "unchanged");
    printf("Handler: %s\n", memcmp(before + 4, after + 4, 4) ? "changed" : "unchanged");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s INPUT\n", argv[0]);
        return 2;
    }
    return copy_input(argv[1]);
}
#endif
