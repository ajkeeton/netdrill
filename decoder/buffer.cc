#include "decoder.h"

const uint32_t BUFFER_INIT_SIZE = 0xffff;
const uint32_t BUFFER_MAX_SIZE = 0xfffffff;

data_buffer_t::data_buffer_t()
{
    buf_data = new uint8_t[BUFFER_INIT_SIZE];
    buf_size = BUFFER_INIT_SIZE;
    buf_cur = buf_end = 0;
}

data_buffer_t::data_buffer_t(const data_buffer_t &dt)
{
    data_buffer_t &d = const_cast<data_buffer_t &>(dt);

    buf_data = d.buf_data;
    d.buf_data = NULL;

    buf_size = d.buf_size;
    buf_end = d.buf_end;
    buf_cur = d.buf_cur;

    d.buf_size = d.buf_end = d.buf_cur = 0;
}

data_buffer_t::~data_buffer_t()
{
    if(buf_data)
        delete buf_data;
}

void data_buffer_t::queue(const uint8_t *data, uint32_t length)
{
    if(length + buf_end > buf_size) {
        if(buf_size * 2 > BUFFER_MAX_SIZE) {
            // XXX
            abort();
        }

        uint8_t *new_buf = new uint8_t[buf_size*2];

        memcpy(new_buf, buf_data, buf_size);

        delete buf_data;
        buf_data = new_buf;

        buf_size *= 2;
    }
    
    memcpy(buf_data + buf_end, data, length);

    buf_end += length;
}

uint8_t *data_buffer_t::read(uint32_t total) 
{
    if(total > (buf_end - buf_cur)) 
        throw Out_of_Bounds(__FILE__, __func__, __LINE__);

    buf_cur += total;

    return buf_data + buf_cur;
}

void data_buffer_t::rewind()
{
    buf_cur = 0;
    buf_end = 0;
}

void data_buffer_t::rewind(uint32_t num)
{
    if(num > buf_cur) {
        throw Out_of_Bounds(__FILE__, __func__, __LINE__);
    }

    buf_cur -= num;
}

