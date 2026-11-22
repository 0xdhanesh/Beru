/*
 * Intentionally vulnerable learning lab: CWE-193 leading to CWE-122.
 * See off_by_one.md for build instructions, boundaries, and the correction.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned char *buffer;
    char *end;
    long parsed;
    size_t count;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s COUNT\n", argv[0]);
        return 2;
    }

    errno = 0;
    parsed = strtol(argv[1], &end, 10);
    if (errno == ERANGE || end == argv[1] || *end != '\0' || parsed < 0) {
        fputs("Expected a nonnegative decimal count representable as long.\n", stderr);
        return 2;
    }
    if (parsed > 65) {
        fputs("Input too long: demonstration maximum is 65 bytes.\n", stderr);
        return 1;
    }
    count = (size_t)parsed;

    /* Keep output observable if the deliberate write damages allocator state. */
    setvbuf(stdout, NULL, _IONBF, 0);
    buffer = malloc(64);
    if (buffer == NULL) {
        fputs("Allocation failed.\n", stderr);
        return 3;
    }
    memset(buffer, '.', 64);

    printf("Count: %zu\n", count);

    /* Deliberate off-by-one: 65 bytes writes one byte past malloc(64). */
    memset(buffer, 'X', count);

    fputs("Buffer: ", stdout);
    fwrite(buffer, 1, 64, stdout);
    putchar('\n');

    if (count > 64) {
        /* Do not perform another allocator operation after the invalid write. */
        fflush(stdout);
        _Exit(0);
    }
    free(buffer);
    return 0;
}
