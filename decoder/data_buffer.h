#pragma once

class data_buffer_t
{
    uint8_t *buf_data;
    uint32_t buf_size;
    uint32_t buf_end;
    uint32_t buf_cur;
    
    const data_buffer_t &operator=(data_buffer_t &);
public:
    data_buffer_t(const data_buffer_t&);
    data_buffer_t();
    ~data_buffer_t();
    void queue(const uint8_t *data, uint32_t length);
    uint8_t *read(uint32_t total);

    uint8_t *start() { return buf_data; }
    uint8_t *current() { return buf_data + buf_cur; }
    uint32_t available() { return buf_end - buf_cur; }
    uint32_t length() { return buf_end; }
    void rewind(uint32_t num);
    void rewind();
};

