#include <stdint.h>


void poke() {
    volatile uint64_t c,d;
    c = 0xaaabadbadbadbeef;
    d = 0xbeefbeefbeefbeef;
    asm volatile("rdrand  %0\n\t"
                 "rdrand  %1": "=r"(c), "=r"(d));
    printf("%016lX", c);
    printf("%016lX\n", d);
}

int main() {
    volatile uint64_t c;
    asm volatile("movabs $0x99a0086fba28dfd1, %%rax\n\t"\
        "movabs $0xe2dd84b5c9688a03, %%rbx\n\t"\
        "movabs $0xffffffff8105c7e0, %%rdx\n\t"\
        "movabs $0xabadbabe00000001, %%rcx\n\t"\
            "add %%rax, %%rbx\n\t"\
            "mov %%rbx, %0" : "=r"(c) : : "rax", "rbx", "rdx", "rcx");
    printf("did ubercall, now printing results\n");
    poke();




}

