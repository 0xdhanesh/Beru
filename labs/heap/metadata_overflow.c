/*
 * Intentionally vulnerable learning lab: CWE-122 / CWE-787.
 * See metadata_overflow.md for glibc layout assumptions and the correction.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

int main(int argc, char **argv) {
    unsigned char *buffer;
    unsigned char *victim;
    char *end;
    long parsed = 0;
    size_t count;
    int automatic;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s COUNT|metadata\n", argv[0]);
        return 2;
    }
    automatic = strcmp(argv[1], "metadata") == 0;
    if (!automatic) {
        errno = 0;
        parsed = strtol(argv[1], &end, 10);
        if (errno == ERANGE || end == argv[1] || *end != '\0' || parsed < 0) {
            fputs("Expected a nonnegative decimal count representable as long, or metadata.\n", stderr);
            return 2;
        }
        if (parsed > 4096) {
            fputs("Input too long: demonstration maximum is 4096 bytes.\n", stderr);
            return 1;
        }
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    buffer = malloc(64);
    victim = malloc(256);
    if (buffer == NULL || victim == NULL) {
        free(victim);
        free(buffer);
        fputs("Allocation failed.\n", stderr);
        return 3;
    }
    memset(buffer, '.', 64);
    memset(victim, 'V', 256);
    count = (size_t)parsed;
    if (automatic) {
        int available = 0;
#if defined(__GLIBC__)
        /* Ordinary glibc chunks: the next size word ends at victim's start.
         * Check the observed stride against usable size, without reading headers
         * or subtracting unrelated C pointers. Interposed allocators may differ.
         */
        uintptr_t start = (uintptr_t)buffer;
        uintptr_t next = (uintptr_t)victim;
        size_t usable = malloc_usable_size(buffer);
        if (next > start && next - start > 64 && next - start <= 4096 &&
            usable >= 64 && usable <= 4096 - sizeof(size_t) &&
            next - start == usable + sizeof(size_t)) {
            count = (size_t)(next - start);
            available = 1;
        }
#endif
        if (!available) {
            free(victim);
            free(buffer);
            fputs("Layout unavailable: metadata mode requires nearby ordinary glibc chunks.\n", stderr);
            return 3;
        }
    }

    printf("Count: %zu\n", count);
    puts("Fill: zero bytes into a 64-byte allocation");
    /* Deliberate bug: count is not checked against the requested capacity. */
    memset(buffer, 0, count);
    puts("Fill completed; freeing victim");
    /* Unlike the adjacent-data labs, deliberately exercise corrupted metadata. */
    free(victim);
    puts("Victim free returned");
    if (count > 64) {
        /* If detection did not terminate us, avoid further allocator operations. */
        _Exit(0);
    }
    free(buffer);
    return 0;
}
