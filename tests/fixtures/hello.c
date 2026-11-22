#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char message[64];
    const char *name = argc > 1 ? argv[1] : "Beru";
    if (strlen(name) >= sizeof(message)) {
        return 1;
    }
    strcpy(message, name);
    puts(message);
    return 0;
}
