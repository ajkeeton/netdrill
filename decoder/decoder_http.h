#pragma once

#include <map>
#include "decoder.h"

class tmod_uri_param_t
{

};

class tmod_http_header_t
{

};

class tmod_http_pkt_t 
{
public:
    tmod_http_pkt_t() 
    {   
        raw = header = body = NULL;
        length = content_length = 0;
        is_request = true;
    }

    char *raw;

    char *header;
    char *body;
    uint32_t content_length,
             length;

    bool is_request;
};

void http_init() ;
