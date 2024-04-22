#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    FILE *fp;
    unsigned long seed;

    if (argc < 2) return EXIT_FAILURE;

    seed = strtoul(argv[1], NULL, 10);
    srand(seed);

    fp = fopen("./gadgets", "w");
    for (int i=0; i<0x4000000; i++) {
        int r = rand();
        fwrite(&r, sizeof(int), 1, fp);
    }
    fclose(fp);
} 
