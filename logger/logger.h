#pragma once
#include <stdio.h>

void tmod_hex_dump(FILE *fp, const uint8_t *data, uint32_t size);
void tmod_hex_dump(const uint8_t *data, uint32_t size);
void tmod_hex_dump(
    char *dst, uint32_t dst_len, const uint8_t *data, uint32_t size);

class tmod_logger_t 
{
    FILE *logfile;
public:
    void payload_save(uint8_t *data, uint32_t length);
    void payload_save_hex(uint8_t *data, uint32_t length);
    void save_pcap(uint8_t *data, uint32_t length);
    void save_hex(uint8_t *data, uint32_t length);

    tmod_logger_t(char *file_path);
    tmod_logger_t();
};

enum tmod_log_level_t 
{
    TMOD_LOG_ERROR,
    TMOD_LOG_INFO,
    TMOD_LOG_DEBUG
};

void TMOD_DEBUG(const char *args, ...);
extern tmod_log_level_t tmod_log_level;

