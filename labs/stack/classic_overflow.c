/*
 * Intentionally vulnerable learning lab: CWE-121 / CWE-120.
 * See classic_overflow.md for builds, expected behavior, and the correction.
 */
#include <stdio.h>
#include <string.h>

static void copy_input(const char *input) {
    char buffer[64];

    /* Deliberate bug: strcpy also copies the NUL, with no capacity check. */
    strcpy(buffer, input);
    printf("Copied: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s INPUT\n", argv[0]);
        return 2;
    }

    copy_input(argv[1]);
    return 0;
}
