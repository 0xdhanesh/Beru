/*
 * Intentionally vulnerable learning lab: CWE-124 / CWE-129.
 * See buffer_underflow.md for builds, boundaries, and the correction.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int write_byte(long index, char value) {
    char buffer[64];

    memset(buffer, '.', sizeof(buffer));

    /* Deliberate bug: checks the upper bound but allows negative indices. */
    if (index >= (long)sizeof(buffer)) {
        fprintf(stderr, "Index out of range: expected 0 through %zu.\n", sizeof(buffer) - 1);
        return 1;
    }

    /* At index -1, this writes one byte immediately before the stack buffer. */
    buffer[index] = value;

    /* The buffer holds raw bytes; print only the valid array contents. */
    fputs("Buffer: ", stdout);
    fwrite(buffer, 1, sizeof(buffer), stdout);
    putchar('\n');
    return 0;
}

int main(int argc, char **argv) {
    char *end;
    long index;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s INDEX BYTE\n", argv[0]);
        return 2;
    }

    errno = 0;
    index = strtol(argv[1], &end, 10);
    if (errno == ERANGE || end == argv[1] || *end != '\0' || strlen(argv[2]) != 1) {
        fputs("Expected a decimal index representable as long and exactly one data byte.\n", stderr);
        return 2;
    }

    return write_byte(index, argv[2][0]);
}
