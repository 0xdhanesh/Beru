/* Check both bounds before indexing the stack buffer in buffer_underflow.c. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int write_byte(long index, char value) {
    char buffer[64];

    memset(buffer, '.', sizeof(buffer));

    if (index < 0 || index >= (long)sizeof(buffer)) {
        fprintf(stderr, "Index out of range: expected 0 through %zu.\n", sizeof(buffer) - 1);
        return 1;
    }

    buffer[index] = value;
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
