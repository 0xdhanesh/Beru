/* Length-checked counterpart to classic_overflow.c. */
#include <stdio.h>
#include <string.h>

static int copy_input(const char *input) {
    char buffer[64];
    const size_t length = strlen(input);

    /* Reserve one byte for the terminating NUL; reject rather than truncate. */
    if (length >= sizeof(buffer)) {
        fprintf(stderr, "Input too long: maximum is %zu bytes.\n", sizeof(buffer) - 1);
        return 1;
    }

    memcpy(buffer, input, length + 1);
    printf("Copied: %s\n", buffer);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s INPUT\n", argv[0]);
        return 2;
    }

    return copy_input(argv[1]);
}
