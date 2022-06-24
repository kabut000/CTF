#include <stdio.h>
#include <stdlib.h>

int main(){
    for(int i=0; ; i++){
        srand(i);
        int key0 = rand() == 306291429;
        int key1 = rand() == 442612432;
        int key2 = rand() == 110107425;

        if (key0 && key1 && key2) {
            printf("%d\n", i);
            return 0;
        }
    }
}
