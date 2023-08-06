#include <iostream>
using namespace std;

int main(){
    long long total;
    cin >> total;
    total &= 0xffffffff;
    for(long long p=0x00000b6c; p<0x100000000; p+=0x1000){
        for(long long q=0x5500; q<0x6000; q++){
            if((p*q&0xffffffff) == total){
                cout << p << " " << q << endl;
                exit(1);
            }
        }
    }
}