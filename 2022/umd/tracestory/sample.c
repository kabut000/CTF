#include <stdio.h>
#include <sys/time.h>

int main(void)
{
    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    while(t2.tv_sec < (t1.tv_sec+1)){
        gettimeofday(&t2, NULL);
        printf("%ld %ld\n", t1.tv_sec, t2.tv_sec);
    }
    return 0;
}