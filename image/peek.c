#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

struct ctrctx {
    uint64_t counter;
    uint8_t aeskey [16];
};

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
    volatile register uint64_t rax asm("rax");
    volatile register uint64_t rbx asm("rbx");
    volatile register uint64_t rcx asm("rcx");
    volatile register uint64_t rdx asm("rdx");
    struct ctrctx ctx;
    uint8_t buf [16];

    ctx.counter = 0;
    memcpy(ctx.aeskey, "YELLOW SUBMARINE", 16);

    rax = 0x99a0086fba28dfd1;
    rbx = 0xe2dd84b5c9688a03;
    rcx = 0xabadbabe00000001;
    rdx = 0xffffffff8105c7e0;

    ctr_output(buf, &ctx);

    rax ^= *((uint64_t *) buf);
    rbx ^= *((uint64_t *) buf + 8);
    ctx.counter++;
    ctr_output(buf, &ctx);
    rcx ^= *((uint64_t *) buf);
    rdx ^= *((uint64_t *) buf + 8);
    asm volatile("add %rax, %rbx");
    printf("did ubercall, now printing results\n");
    poke();
}

void ctr_output(uint8_t *output, struct ctrctx *ctx) {
    uint8_t ibuf [16];

    AES_KEY keyctx;
    AES_set_encrypt_key(ctx->aeskey, 128, &keyctx);

    memset(ibuf, 0xef, 16);
    memcpy(ibuf, &(ctx->counter), 8);
    AES_encrypt(ibuf, output, &keyctx);
}



