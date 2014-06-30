#include <stdint.h>

int main() {
    volatile uint64_t c,d;

    asm volatile("rdrand  %0\n\t"
                 "rdrand  %1": "=r"(c), "=r"(d));
    printf("%p\n", c);
    printf("%p\n", d);
}


