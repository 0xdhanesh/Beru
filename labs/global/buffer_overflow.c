/*
 * Intentionally vulnerable learning lab: CWE-787 / CWE-120.
 * See buffer_overflow.md for builds, observations, and the correction.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Static storage duration; a structure gives the members a specified order. */
struct lab_storage {
    char buffer[64];
    unsigned char adjacent[8];
};

static struct lab_storage storage = { .buffer = {0}, .adjacent = {'S', 'E', 'N', 'T', 'I', 'N', 'E', 'L'} };

_Static_assert(offsetof(struct lab_storage, adjacent) == 64, "Unexpected marker offset");
_Static_assert(sizeof(storage) == 72, "Unexpected storage padding");

static int copy_input(const char *input) {
    const size_t length = strlen(input);

    /* Deliberate bug: no capacity check, including for the terminating NUL. */
    strcpy(storage.buffer, input);

    /* Never treat the possibly overwritten marker as a terminated string. */
    printf("Copied: %zu bytes\nAdjacent:", length);
    for (size_t i = 0; i < sizeof(storage.adjacent); ++i) {
        printf(" %02x", (unsigned int)storage.adjacent[i]);
    }
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
