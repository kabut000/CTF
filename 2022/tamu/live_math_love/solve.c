#include <stdio.h>
#include <string.h>

int main() {
    int win = 0x401162;
    float f = 0;
    memcpy((void *)&f, (void *)&win, 4);
    printf("%e\n", f);
    return 0;
}