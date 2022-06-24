//  gcc mirror.c -o mirror -no-pie

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    int N, n, i, p, f;
    char *buf, c;

    scanf("%d", &N);
    for (i=0; i<N; i++) {
        scanf("%d", &n);
        getchar();  // ' '
        buf = malloc(n);
        memset(buf, 0, n);
        //  A
        p = 0;
        for (;;) {
            c = getchar();
            if (c==' ')
                break;
            buf[p++] += c;
        }
        //  B
        for (;;) {
            c = getchar();
            if (c=='\n')
                break;
            buf[--p] -= c;
        }
        //  check
        f = 1;
        for (p=0; p<=n; p++)
            if (buf[p]!='\0')
                f = 0;
        free(buf);
        if (f)
            puts("mirror");
        else
            puts("no");
    }
    return 0;
}
