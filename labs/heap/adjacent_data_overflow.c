/*
 * Intentionally vulnerable learning lab: CWE-122 / CWE-787.
 * See adjacent_data_overflow.md for allocator assumptions and the correction.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned char *buffer;
    unsigned char *marker;
    char *end;
    long parsed = 0;
    size_t count;
    uintptr_t distance = 0;
    int forward;
    int automatic;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s COUNT|adjacent BYTE\n", argv[0]);
        return 2;
    }
    automatic = strcmp(argv[1], "adjacent") == 0;
    if (!automatic) {
        errno = 0;
        parsed = strtol(argv[1], &end, 10);
        if (errno == ERANGE || end == argv[1] || *end != '\0' || parsed < 0) {
            fputs("Expected a nonnegative decimal count representable as long, or adjacent.\n", stderr);
            return 2;
        }
    }
    if (strlen(argv[2]) != 1) {
        fputs("Expected exactly one data byte.\n", stderr);
        return 2;
    }
    if (!automatic && parsed > 4096) {
        fputs("Input too long: demonstration maximum is 4096 bytes.\n", stderr);
        return 1;
    }

    /* Avoid allocating a stdout buffer after an intentional heap overwrite. */
    setvbuf(stdout, NULL, _IONBF, 0);
    buffer = malloc(64);
    marker = malloc(8);
    if (buffer == NULL || marker == NULL) {
        free(marker);
        free(buffer);
        fputs("Allocation failed.\n", stderr);
        return 3;
    }
    memset(buffer, '.', 64);
    memcpy(marker, "SENTINEL", 8);

    /* Subtract integer address representations, never unrelated C pointers. */
    forward = (uintptr_t)marker > (uintptr_t)buffer;
    if (forward) {
        distance = (uintptr_t)marker - (uintptr_t)buffer;
        forward = distance >= 64;
    }
    if (automatic) {
        /* Only select a nearby, forward allocation observed in this process. */
        if (!forward || distance >= 4096) {
            free(marker);
            free(buffer);
            fputs("Layout unavailable: marker is not within 4095 bytes after the buffer.\n", stderr);
            return 3;
        }
        count = (size_t)distance + 1;
    } else {
        count = (size_t)parsed;
    }


    printf("Count: %zu\n", count);
    if (forward) {
        printf("Forward distance: %llu\n", (unsigned long long)distance);
    } else {
        puts("Forward distance: unavailable");
    }

    /* Deliberate bug: no check against the 64-byte destination allocation. */
    memset(buffer, (unsigned char)argv[2][0], count);

    fputs("Buffer: ", stdout);
    fwrite(buffer, 1, 64, stdout);
    fputs("\nMarker:", stdout);
    for (size_t i = 0; i < 8; ++i) {
        printf(" %02x", (unsigned int)marker[i]);
    }
    putchar('\n');

    if (count > 64) {
        /* Allocator metadata may be damaged. Do not free or run exit handlers. */
        fflush(stdout);
        _Exit(0);
    }
    free(marker);
    free(buffer);
    return 0;
}
