/* Check both bounds before reading the stack buffer in out_of_bounds_read.c. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int read_byte(long index) {
    unsigned char buffer[64];

    for (size_t i = 0; i < sizeof(buffer); ++i) {
        buffer[i] = (unsigned char)i;
    }

    if (index < 0 || index >= (long)sizeof(buffer)) {
        fprintf(stderr, "Index out of range: expected 0 through %zu.\n", sizeof(buffer) - 1);
        return 1;
    }

    printf("Byte[%ld]: 0x%02x\n", index, (unsigned int)buffer[index]);
    return 0;
}

int main(int argc, char **argv) {
    char *end;
    long index;

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

    return read_byte(index);
}
