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

class tmod_http_t 
{
    tmod_http_t(const tmod_http_t &);
    bool is_client_side(data_buffer_t &b) { return &b == client_buffer; }
    // proto_id_t identify(const uint8_t *data, uint32_t length);
    bool find_header_end(data_buffer_t &b);
    bool parse_header(data_buffer_t &b);
    bool find_body_end(data_buffer_t &b);
    bool parse_body(data_buffer_t &b);
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
    bool decode(data_buffer_t &b);

    uint32_t content_length,
             content_remaining,
             body_length,
             body_offset,
             header_offset,
             length;

    data_buffer_t *client_buffer;
    data_buffer_t *server_buffer;

    bool is_request,
         header_complete,
         body_complete,
         is_chunked;
};

