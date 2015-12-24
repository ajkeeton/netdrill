#pragma once

#include <map>
#include "decoder.h"

class tmod_uri_param_t
{

};

class tmod_http_header_t
{

};

void http_init() ;

class http_data_buffer_t : public data_buffer_t 
{
public:
    http_data_buffer_t();
    void init();
    bool complete() {
        return header_complete && body_complete;
    }

    uint32_t content_length,
             content_remaining,
             body_length,
             body_offset,
             header_offset,
             length;

    bool header_complete,
         body_complete,
         is_chunked;
};

class tmod_http_t 
{
    tmod_http_t(const tmod_http_t &);
    bool is_client_side(http_data_buffer_t &b) { return &b == client_buffer; }
    // proto_id_t identify(const uint8_t *data, uint32_t length);
    bool find_header_end(http_data_buffer_t &b);
    bool parse_header(http_data_buffer_t &b);
    bool find_body_end(http_data_buffer_t &b);
    bool parse_body(http_data_buffer_t &b);
    void init();
    tmod_http_t(tmod_pkt_t &pkt);

public:
    tmod_http_t() 
    {   
        init();
    }

    ~tmod_http_t() 
    {
        if(client_buffer)
            delete client_buffer;
        if(server_buffer)
            delete server_buffer;
    }

    void purge();
    bool decode(const uint8_t *data, uint32_t length);
    bool decode(http_data_buffer_t &b);

    http_data_buffer_t *client_buffer;
    http_data_buffer_t *server_buffer;
};

