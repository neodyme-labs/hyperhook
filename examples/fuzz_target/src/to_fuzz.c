#include <stdio.h>
#include <stdlib.h>

int hook_me_1(int arg1) {
    printf("Hook me called with arg1: %d\n", arg1);
    return 1;
}

int fuzz_case(char* data, int len) {
    if(len < 4) return -1;
    if(data[0] == 'N') {
        if(data[1] == 'E') {
            if(data[2] == '0') {
                if(data[3] == 'D') {
                    if(data[4] == 'y') {
                        if(data[5] == 'M') {
                            if(data[6] == 'E') {
                            int* myPTR = NULL;
                            *myPTR = 0x13371338;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}


int main() {
   printf("Program startup\n");

   int res = hook_me_1(1338);
   printf("Hook me returned: %d\n", res);

   char* buf_input = (char*)malloc(0x1000);
   fuzz_case(buf_input, 0x10);

   return 0;
}