#include <stdint.h>

int main() {
    volatile uint64_t c;

    asm volatile("rdrand  %0" : "=r"(c));


    
    printf("%p\n", c);
}


