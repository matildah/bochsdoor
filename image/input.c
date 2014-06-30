#include <stdint.h>

int main() {
    volatile uint64_t c;
    asm("movabs $0x99a0086fba28dfd1, %%rax\n\t"\
        "movabs $0xe2dd84b5c9688a03, %%rbx\n\t"\
            "add %%rax, %%rbx\n\t"\
            "mov %%rbx, %0" : "=r"(c) : : "rax", "rbx");

    
    printf("%p\n", c);
}


