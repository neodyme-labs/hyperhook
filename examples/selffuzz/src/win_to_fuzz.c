#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


__declspec( dllexport ) int fuzz_case(char* data, int len) {
    if(len < 7) return -1;
        if(data[0] == 'N') {
            if(data[1] == 'E') {
                if(data[2] == '0') {
                    if(data[3] == 'D') {
                        if(data[4] == 'y') {
                            if(data[5] == 'M') {
                                if(data[6] == 'E') {
                                *((uint32_t*)0x00) = 0x13371338;
                                }
                            }
                        }
                    }
                }
            }
        }

        if(data[0] == 'T') {
            if(data[1] == '1') {
                if(data[2] == 'M') {
                    if(data[3] == 'e') {
                        if(data[4] == 'O') {
                            if(data[5] == 'U') {
                                if(data[6] == 'T') {
                                    while (1) {

                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
}
 
