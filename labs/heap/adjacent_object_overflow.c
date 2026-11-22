/*
 * Intentionally vulnerable learning lab: CWE-122 / CWE-787.
 * See adjacent_object_overflow.md for layout assumptions and the correction.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*callback_fn)(void);

struct lab_object {
    callback_fn callback;
};

static void original_callback(void) {
    puts("Callback: original");
}

static void replacement_callback(void) {
    puts("Callback: replacement");
}

int main(int argc, char **argv) {
    unsigned char *buffer;
    struct lab_object *object;
    unsigned char payload[4096];
    callback_fn original = original_callback;
    callback_fn replacement = replacement_callback;
    char *end;
    long parsed = 0;
    size_t count;
    uintptr_t distance = 0;
    int forward;
    int automatic;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s COUNT|adjacent\n", argv[0]);
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
        if (parsed > 4096) {
            fputs("Input too long: demonstration maximum is 4096 bytes.\n", stderr);
            return 1;
        }
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    buffer = malloc(64);
    object = malloc(sizeof(*object));
    if (buffer == NULL || object == NULL) {
        free(object);
        free(buffer);
        fputs("Allocation failed.\n", stderr);
        return 3;
    }
    memset(buffer, '.', 64);
    /* Copy a real function-pointer representation, including any padding. */
    memcpy(&object->callback, &original, sizeof(original));
    memset(payload, 'X', sizeof(payload));

    /* Integer address observations only: never subtract unrelated pointers. */
    forward = (uintptr_t)object > (uintptr_t)buffer;
    if (forward) {
        distance = (uintptr_t)object - (uintptr_t)buffer;
        forward = distance >= 64;
    }
    if (automatic) {
        if (!forward || sizeof(replacement) > sizeof(payload) ||
            distance > sizeof(payload) - sizeof(replacement)) {
            free(object);
            free(buffer);
            fputs("Layout unavailable: callback is not within the forward demonstration range.\n", stderr);
            return 3;
        }
        count = (size_t)distance + sizeof(replacement);
        /* No integer/function-pointer casts, guessed addresses, or CLI NUL bytes. */
        memcpy(payload + (size_t)distance, &replacement, sizeof(replacement));
    } else {
        count = (size_t)parsed;
    }

    printf("Count: %zu\n", count);
    if (forward) {
        printf("Forward distance: %llu\n", (unsigned long long)distance);
    } else {
        puts("Forward distance: unavailable");
    }
    printf("Callback bytes: %zu\n", sizeof(original));

    /* Deliberate bug: count is not checked against the 64-byte allocation. */
    memcpy(buffer, payload, count);

    /* Inspect bytes before loading a potentially invalid function pointer. */
    if (memcmp(&object->callback, &original, sizeof(original)) == 0 ||
        memcmp(&object->callback, &replacement, sizeof(replacement)) == 0) {
        object->callback();
    } else {
        puts("Callback: unrecognized bytes; call skipped");
    }

    if (count > 64) {
        /* The overwrite may damage allocator metadata; skip heap cleanup. */
        fflush(stdout);
        _Exit(0);
    }
    free(object);
    free(buffer);
    return 0;
}
