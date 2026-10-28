static __forceinline int inline_leaf(int value) {
    volatile int a=value*7;
    return a+3;
}
static __forceinline int inline_parent(int value) {
    return inline_leaf(value)+11;
}
__declspec(noinline) int blackbox_outer(int value) {
    int one=inline_parent(value);
    volatile int two=one+5;
    return two;
}
void entry(void) { volatile int value=blackbox_outer(5); (void)value; }
