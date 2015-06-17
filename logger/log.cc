#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void hex_dump(const uint8_t *data, int size)
{
    if(size <= 0) return;

    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};

    for (n= 1; n <= size; n++) {
        if (n % 16 == 1) {
        // store address for this line 
            snprintf(addrstr, sizeof(addrstr), "%.4x", 
                    (uint32_t)(p - (uint8_t*)data) );
        }

        c = *p;
        if (isalnum(c) == 0 && c != ' ') {
            c = '.';
        }

        // store hex str (for left side) 
        snprintf(bytestr, sizeof(bytestr), "%02X%s", *p, (n % 2 == 0) ? " " : "");
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        // store char str (for right side)
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if (n % 16 == 0) { 
            // line completed
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } 
        else if (n % 8 == 0) {
            //half line: add whitespaces
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; // next byte 
    }

    if (strlen(hexstr) > 0) {
        // print rest of buffer if not empty 
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }

    fflush(stdout);
}

