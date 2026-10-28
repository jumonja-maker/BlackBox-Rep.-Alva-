/* Deliberately controlled native QA workload. No imports, file access or network.
 * -- compile normally: terminates; -DBLACKBOX_QA_BUSY: owned CI process only.
 */
__declspec(noinline) int blackbox_leaf(int value) {
    volatile int result = value * 7;
    return result + 3;
}
__declspec(noinline) int blackbox_parent(int value) {
    volatile int sum = 0;
    for (int i = 0; i < 1000; ++i) sum += blackbox_leaf((value + i) & 1023);
    return sum;
}
void entry(void) {
    volatile int result = 0;
#ifdef BLACKBOX_QA_BUSY
    for (;;) result = blackbox_parent(result & 1023);
#else
    result = blackbox_parent(5);
#endif
    (void)result;
}
