/* Bounds-checked counterpart to out_of_bounds_read.c. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    unsigned char *buffer;
    char *end;
    long index;
    const size_t capacity = 64;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s INDEX\n", argv[0]);
        return 2;
    }

    errno = 0;
    index = strtol(argv[1], &end, 10);
    if (errno == ERANGE || end == argv[1] || *end != '\0') {
        fputs("Expected a decimal index representable as long.\n", stderr);
        return 2;
    }
    if (index < 0 || index >= (long)capacity) {
        fprintf(stderr, "Index out of range: expected 0 through %zu.\n", capacity - 1);
        return 1;
    }

    buffer = malloc(capacity);
    if (buffer == NULL) {
        fputs("Allocation failed.\n", stderr);
        return 3;
    }
    for (size_t i = 0; i < capacity; ++i) {
        buffer[i] = (unsigned char)i;
    }

    printf("Byte[%ld]: 0x%02x\n", index, (unsigned int)buffer[index]);
    free(buffer);
    return 0;
}
