/*
 * Intentionally vulnerable learning lab: CWE-124 / CWE-129.
 * See buffer_underflow.md for build instructions, boundaries, and the correction.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned char *buffer;
    char *end;
    long index;
    const size_t capacity = 64;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s INDEX BYTE\n", argv[0]);
        return 2;
    }

    errno = 0;
    index = strtol(argv[1], &end, 10);
    if (errno == ERANGE || end == argv[1] || *end != '\0' ||
        strlen(argv[2]) != 1) {
        fputs("Expected a decimal index representable as long and exactly one data byte.\n",
              stderr);
        return 2;
    }
    if (index >= (long)capacity) {
        fprintf(stderr, "Index out of range: expected 0 through %zu.\n", capacity - 1);
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    buffer = malloc(capacity);
    if (buffer == NULL) {
        fputs("Allocation failed.\n", stderr);
        return 3;
    }
    memset(buffer, '.', capacity);

    /* Deliberate bug: the upper bound is checked, but negative indices are allowed. */
    buffer[index] = (unsigned char)argv[2][0];

    fputs("Buffer: ", stdout);
    fwrite(buffer, 1, capacity, stdout);
    putchar('\n');

    if (index < 0) {
        /* Do not perform another allocator operation after the invalid write. */
        fflush(stdout);
        _Exit(0);
    }
    free(buffer);
    return 0;
}
