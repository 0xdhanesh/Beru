/* Bounds-checked counterpart to off_by_null.c. */
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
    if (length >= capacity) {
        fprintf(stderr, "Input too long: maximum is %zu bytes.\n", capacity - 1);
        return 1;
    }

    buffer = malloc(capacity);
    if (buffer == NULL) {
        fputs("Allocation failed.\n", stderr);
        return 3;
    }

    memcpy(buffer, argv[1], length + 1);
    fputs("Copied: ", stdout);
    fwrite(buffer, 1, length, stdout);
    putchar('\n');

    free(buffer);
    return 0;
}
