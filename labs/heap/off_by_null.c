/*
 * Intentionally vulnerable learning lab: CWE-193 leading to CWE-122.
 * See off_by_null.md for build instructions, boundaries, and the correction.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned char *buffer;
    const size_t capacity = 64;
    size_t length;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s INPUT\n", argv[0]);
        return 2;
    }

    length = strlen(argv[1]);
    if (length > capacity) {
        fprintf(stderr, "Input too long: maximum is %zu bytes.\n", capacity);
        return 1;
    }

    /* Keep output observable if the deliberate write damages allocator state. */
    setvbuf(stdout, NULL, _IONBF, 0);
    buffer = malloc(capacity);
    if (buffer == NULL) {
        fputs("Allocation failed.\n", stderr);
        return 3;
    }

    /* Deliberate off-by-null: at length 64, the NUL lands at buffer[64]. */
    memcpy(buffer, argv[1], length + 1);

    fputs("Copied: ", stdout);
    fwrite(buffer, 1, length, stdout);
    putchar('\n');

    if (length == capacity) {
        /* Do not perform another allocator operation after the invalid write. */
        fflush(stdout);
        _Exit(0);
    }
    free(buffer);
    return 0;
}
