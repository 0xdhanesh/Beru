/*
 * Intentionally vulnerable learning lab: CWE-124 / CWE-129.
 * See buffer_underflow.md for builds, boundaries, and the correction.
 */
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Static storage duration; do not assume separate globals are adjacent. */
struct lab_storage {
    unsigned char preceding[8];
    char buffer[64];
};

static struct lab_storage storage = {
    .preceding = {'S', 'E', 'N', 'T', 'I', 'N', 'E', 'L'}, .buffer = {0}
};

_Static_assert(offsetof(struct lab_storage, buffer) == 8, "Unexpected buffer offset");
_Static_assert(sizeof(struct lab_storage) == 72, "Unexpected storage padding");

static int write_byte(long index, char value) {
    memset(storage.buffer, '.', sizeof(storage.buffer));

    /* Deliberate bug: checks the upper bound but allows negative indices. */
    if (index >= (long)sizeof(storage.buffer)) {
        fprintf(stderr, "Index out of range: expected 0 through %zu.\n", sizeof(storage.buffer) - 1);
        return 1;
    }

    /* Index -1 writes into the last byte of the preceding static marker. */
    storage.buffer[index] = value;

    /* Print only valid array contents; neither field is a C string. */
    fputs("Buffer: ", stdout);
    fwrite(storage.buffer, 1, sizeof(storage.buffer), stdout);
    fputs("\nPreceding:", stdout);
    for (size_t i = 0; i < sizeof(storage.preceding); ++i) {
        printf(" %02x", (unsigned int)storage.preceding[i]);
    }
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
