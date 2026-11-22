/*
 * Intentionally vulnerable learning lab: CWE-193 leading to CWE-121.
 * See off_by_null.md for builds, boundaries, and the correction.
 */
#include <stdio.h>
#include <string.h>

static int copy_input(const char *input) {
    char buffer[64];
    const size_t length = strlen(input);

    /* Deliberate bug: allows 64 data bytes without reserving room for the NUL. */
    if (length > sizeof(buffer)) {
        fprintf(stderr, "Input too long: maximum is %zu bytes.\n", sizeof(buffer));
        return 1;
    }

    /* At length 64, the data fits but the terminating NUL lands at buffer[64]. */
    memcpy(buffer, input, length + 1);

    /* Use the data length to avoid a second, out-of-bounds string read. */
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
