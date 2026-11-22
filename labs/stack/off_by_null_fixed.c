/* Reserve space for the terminating NUL in off_by_null.c. */
#include <stdio.h>
#include <string.h>

static int copy_input(const char *input) {
    char buffer[64];
    const size_t length = strlen(input);

    if (length >= sizeof(buffer)) {
        fprintf(stderr, "Input too long: maximum is %zu bytes.\n", sizeof(buffer) - 1);
        return 1;
    }

    memcpy(buffer, input, length + 1);
    fputs("Copied: ", stdout);
    fwrite(buffer, 1, length, stdout);
    putchar('\n');
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s INPUT\n", argv[0]);
        return 2;
    }

    return copy_input(argv[1]);
}
