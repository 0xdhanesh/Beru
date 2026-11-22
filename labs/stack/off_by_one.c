/*
 * Intentionally vulnerable learning lab: CWE-193 leading to CWE-121.
 * See off_by_one.md for builds, boundaries, and the correction.
 */
#include <stdio.h>
#include <string.h>

static int copy_input(const char *input) {
    char buffer[64];
    const size_t length = strlen(input);

    /* Deliberate off-by-one: a 64-byte buffer cannot hold 65 data bytes. */
    if (length > sizeof(buffer) + 1) {
        fprintf(stderr, "Input too long: maximum is %zu bytes.\n", sizeof(buffer) + 1);
        return 1;
    }

    /* Copy raw data only, without a NUL: at length 65, exactly one byte overflows. */
    memcpy(buffer, input, length);

    /* Limit output to the buffer capacity to avoid a second, out-of-bounds read. */
    fputs("Copied: ", stdout);
    fwrite(buffer, 1, length < sizeof(buffer) ? length : sizeof(buffer), stdout);
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
