/* This C11 syntax also ensures mixed builds compile .c files as C. */
int answer(void) {
    _Static_assert(sizeof(int) >= 2, "int too small");
    return 42;
}
