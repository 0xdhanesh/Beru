/* Bounds-checked counterpart to off_by_one.c. */
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
    if (parsed > 64) {
        fputs("Input too long: maximum is 64 bytes.\n", stderr);
        return 1;
    }
    count = (size_t)parsed;

    setvbuf(stdout, NULL, _IONBF, 0);
    buffer = malloc(64);
    if (buffer == NULL) {
        fputs("Allocation failed.\n", stderr);
        return 3;
    }
    memset(buffer, '.', 64);

    printf("Count: %zu\n", count);
    memset(buffer, 'X', count);

    fputs("Buffer: ", stdout);
    fwrite(buffer, 1, 64, stdout);
    putchar('\n');

    free(buffer);
    return 0;
}
