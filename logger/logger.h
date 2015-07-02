#pragma once

void tmod_hex_dump(FILE *fp, const uint8_t *data, uint32_t size);
void tmod_hex_dump(const uint8_t *data, uint32_t size);

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
