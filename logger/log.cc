#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <stdarg.h>
#include "logger.h"

const char *DEFAULT_SAVEFILE = "/tmp/tmod.log";
tmod_log_level_t tmod_log_level = TMOD_LOG_ERROR;

void tmod_hex_dump(
    char *dst, uint32_t dst_len, const uint8_t *data, uint32_t size)
{
    if(size <= 0) return;

    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    uint32_t offset = 0;

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
            offset += snprintf(dst + offset, 
                dst_len - offset, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
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
        snprintf(dst + offset, dst_len - offset, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

void tmod_hex_dump(FILE *fd, const uint8_t *data, uint32_t size)
{
    char dstbuf[size*6];

    tmod_hex_dump(dstbuf, sizeof(dstbuf), data, size);

    fprintf(fd, dstbuf);
}

void tmod_hex_dump(const uint8_t *data, uint32_t size)
{
    tmod_hex_dump(stdout, data, size);
}

void tmod_logger_t::payload_save(uint8_t *data, uint32_t length)
{

}

void tmod_logger_t::payload_save_hex(uint8_t *data, uint32_t length)
{

}

void tmod_logger_t::save_pcap(uint8_t *data, uint32_t length)
{

}

void tmod_logger_t::save_hex(uint8_t *data, uint32_t length)
{
    tmod_hex_dump(logfile, data, length);
}

tmod_logger_t::tmod_logger_t()
{
    char filename[strlen(DEFAULT_SAVEFILE) + 256];

    sprintf(filename, "%s.0", DEFAULT_SAVEFILE);

    /* Resolve case where there are duplicate filenames */
    struct stat st; 
    uint32_t x = 0;

    while(stat(filename, &st) == 0) {
        sprintf(filename, "%s.%u", DEFAULT_SAVEFILE, x++);
    }

    logfile = fopen(filename, "w");
    
    if(!logfile) {
        printf("Could not open %s for logging. Bailing\n", filename);
        /* XXX No good. Refactor. */
        exit(-1);
    }
}

tmod_logger_t::tmod_logger_t(char *filename)
{
    logfile = fopen(filename, "w");
    
    if(!logfile) {
        printf("Could not open %s for logging. Bailing\n", filename);
        /* XXX refactor. */
        exit(-1);
    }
}

void TMOD_DEBUG(const char *args, ...)
{
    if(TMOD_LOG_DEBUG >= tmod_log_level) return;

    char buf[2048];
    va_list ap;
    int end;
    va_start(ap, args);
    end = vsnprintf(buf, sizeof(buf)-1, args, ap);
    buf[end] = 0; 

    printf("%s", buf);

    va_end(ap);
}
