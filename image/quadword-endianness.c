/* reads in some quadwords and swaps their endianness */
#include <stdint.h>

int main() {
    uint8_t buf[8];

    while(8 == read(0, buf, 8)) {
        write(1, &buf[7], 1);
        write(1, &buf[6], 1);
        write(1, &buf[5], 1);
        write(1, &buf[4], 1);
        write(1, &buf[3], 1);
        write(1, &buf[2], 1);
        write(1, &buf[1], 1);
        write(1, &buf[0], 1);
    }
}

