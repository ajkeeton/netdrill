#include <ctype.h>
#include <assert.h>
#include "ahocorasick.h"
#include "decoder_http.h"

static const string http_log_file_prefix = "/tmp/tmod-http";

static const uint32_t MIN_HEADER_PARSE_SIZE = 8; 
/* ^ Room for a "GET \r\n\r\n". Completely bogus case. Revisit for something
   more reasonable */

const static AC_ALPHABET_t *http_header_patterns[] =
{
    "X-Forwarded-For:",
    "Content-Length:",
    "content-length:",
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: Chunked",
    "transfer-encoding: chunked",
    "transfer-encoding: Chunked",
    "\r\n\r\n", // <- End of header
};

const AC_ALPHABET_t *http_method_patterns[] =
{
     "GET ",
     "POST ",
     "PUT ",
     "DELETE ",
     "HEAD ",
     "OPTIONS ",
     "TRACE ",
     "CONNECT ",
     "HTTP" // <- Not a method, but I don't want to add handling for this one case.
};

static AC_TRIE_t *http_headers;
static AC_TRIE_t *http_requests;

static AC_TRIE_t *ahc_alloc(const AC_ALPHABET_t **alphabet, uint32_t size)
{
    AC_TRIE_t *retval = ac_trie_create();

    for(uint32_t i=0; i<size; i++) {
        uint32_t curlen = strlen(alphabet[i]);
                
        AC_PATTERN_t pattern;
        pattern.ptext.astring = alphabet[i];
        pattern.ptext.length = curlen;
        pattern.rtext.astring = NULL;
        pattern.rtext.length = 0;
        
        pattern.id.u.number = i;
        pattern.id.type = AC_PATTID_TYPE_NUMBER;

        ac_trie_add(retval, &pattern, 0);
    }

    ac_trie_finalize(retval);

    return retval;
}

void http_init() 
{
    http_headers = ahc_alloc(http_header_patterns, sizeof(http_header_patterns) / sizeof(AC_ALPHABET_t*));
    http_requests = ahc_alloc(http_method_patterns, sizeof(http_method_patterns) / sizeof(AC_ALPHABET_t*));
}

void tmod_http_cleanup(void *p)
{
    if(p)
        delete (tmod_http_t*)p;
}

proto_id_t identify(const uint8_t *data, uint32_t length)
{
    /* Make sure it's long enough to be useful */
    if(length < 4) {
        // XXX Technically we would want to buffer this and try again.
        // Not presently supported.
        // buffer->queue(data, length);
        return PROTO_UNKNOWN;
    }

    /* Strip any potential leading whitespace? */

    /* If this is raw binary or a digit, it's not an HTTP request */
    if(!isalpha(data[0])) {
        return PROTO_NOT;
    }
  
    /* Check for valid request/response string */

    AC_TEXT_t input;
    input.astring = (char*)data;
    input.length = length > sizeof("OPTIONS ") ? sizeof("OPTIONS ") : length;
    /* ^ Worst case we only need to check 8 characters, which is the length of
         the longest request, "OPTIONS" */

    ac_trie_settext(http_requests, &input, 0);

    AC_MATCH_t match;

    if((match = ac_trie_findnext(http_requests)).size) {
        /* Make sure it's the first string in the buffer-> */
        if((match.position - strlen(match.patterns[0].ptext.astring)) == 0) {
            return PROTO_HTTP;
        }
    }

    return PROTO_NOT;
}

bool decode_http(tmod_pkt_t &pkt) 
{ 
    /* XXX Add special handling for missing packets. Current version assumes
       all or nothing. */ 
    // if(pkt.flags & GAPPED)
    //  "re-sync" by looking for start of request/response

    tmod_http_t *http; 

    switch(pkt.ssn->protocol()) {
        case PROTO_UNSUPPORTED:
            return false;
        case PROTO_HTTP:
            http = (tmod_http_t*)pkt.ssn->data;
            break;
        case PROTO_UNKNOWN:
            switch(identify(pkt.payload, pkt.payload_size)) {
                case PROTO_HTTP: 
                    pkt.ssn->set_protocol(PROTO_HTTP);
                    http = new tmod_http_t;
                    // XXX pkt.ssn->init(http, tmod_http_cleanup);
                    pkt.ssn->data = (void*)http;
                    pkt.ssn->cleanup_cb = tmod_http_cleanup;
                    break;
                case PROTO_UNKNOWN:
                    return false;
                case PROTO_NOT:
                    return false;
                default:
                    // XXX Generic error exception here
                    break;
            }
            break;
        default:
            return false;
    }
    
    if(pkt.is_tcp_client_side()) {
        http->client_buffer->queue(pkt.payload, pkt.payload_size);
        return http->decode(*http->client_buffer);
    }
    else {
        http->server_buffer->queue(pkt.payload, pkt.payload_size);
        return http->decode(*http->server_buffer);
    }
}

static inline bool http_header_val_to_int(
    const char *data, uint32_t size, uint32_t *retval)
{
    uint32_t offset;

    /* Skip whitespace */
    for(offset = 0; offset < size && isspace(data[offset]); offset++) ;

    if(offset >= size) 
        return false;
    
    char *end;

    *retval = strtol(data + offset, &end, 10);

    if(data + offset == end)
        return false;

    return true;
}

void tmod_http_t::init()
{
    length = body_length = content_length = 
        content_remaining = body_offset = header_offset = 0;
    is_request = true;
    is_chunked = false;
    header_complete = body_complete = false;
    client_buffer = new data_buffer_t();
    server_buffer = new data_buffer_t();
}

#if 0
tmod_http_t::tmod_http_t(tmod_pkt_t &pkt)
{
    init();
}
#endif

bool tmod_http_t::find_header_end(data_buffer_t &buf)
{
    uint32_t length = buf.available();

    if(length < MIN_HEADER_PARSE_SIZE)
        return false;

    AC_TEXT_t input;
    input.astring = (char*)buf.current();
    input.length = length;

    ac_trie_settext(http_headers, &input, 0);

    AC_MATCH_t match;

    bool retval = false;
   
    // XXX See multifast examples
    #warning All of this can be cleaned up significantly by using the API correctly
    // XXX

    while((match = ac_trie_findnext(http_headers)).size && !retval) {
        /* XXX the rest?
           Only one we care about for now... */

        for(uint32_t i=0; i < match.size; i++) {
            AC_PATTERN_t *pp = &match.patterns[i];

            /* XXX Should be able to do this using the index of the string
                   in the original data struct instead */
            if(!strcmp(pp->ptext.astring, "\r\n\r\n")) {
                header_complete = true;
                // XXX Not 100% confident here...
                body_offset = match.position;
                retval = true;
                //bytes_read = match.position;
                break;
            }
            else if(!strcasecmp(pp->ptext.astring, "Content-Length:")) {
                uint32_t tmp;

                if(!http_header_val_to_int(
                        input.astring + match.position, input.length - match.position, &tmp)) {
                    throw Proto_Error(__FILE__, __func__, __LINE__);
                }

                content_length = tmp;
                content_remaining = tmp;
            }
            else if(!strcasecmp(pp->ptext.astring, "Transfer")) {
                is_chunked = true;
            }
        }
    }

    if(body_complete && !header_complete)
        throw Proto_Error(__FILE__, __func__, __LINE__);

    /* Move buffer forward */
    buf.read(length);

    return retval;
}

bool tmod_http_t::parse_header(data_buffer_t &buf)
{
    assert(!header_complete);

    /* Pick out any headers of interest, decode URL, etc. */
    // TODO

    /* Find header end */
    if(find_header_end(buf))
        return true;

    /* End not in sight, back up */
    try {
        buf.rewind(strlen("Content-Length: "));
    }
    catch(Out_of_Bounds&o) {
        /* This is okay. We might just not have enough buffered */
        buf.rewind();
    }

    return false;
}

bool tmod_http_t::parse_body(data_buffer_t &buf)
{
    bool retval = false;

    if(is_chunked && content_length)
        /* XXX Is there any valid case where we'd have both? */
        throw Proto_Error(__FILE__, __func__, __LINE__);

    uint32_t avail = buf.available();

    if(is_chunked) {
        // TODO
        throw Unsupported(__FILE__, __func__, __LINE__);
    }
    else if(content_length) {
        /* Check if we have enough in the buffer. */
        //if(avail >= content_length) {
        if(avail >= content_remaining) {
            body_complete = true;
            retval = true;
            buf.read(content_remaining);
            content_remaining = 0;
        }
        else {
            content_remaining = avail;
            buf.read(avail);
        }
    }
    else {
        body_complete = true;
        retval = true;
    }

#if 0
Need to advance 'cur' as we go for large bodies to prevent backtracking
At start of func:

    [last body][current header][partial body]
               ^ cur                        ^end

End of func should be:

    [last body][current header][partial body]
                                            ^end
                                            ^cur
And then:

    [last body][current header][     body         ][next header][body]
                                            ^ cur                    ^end
#endif

    return retval;
}

bool tmod_http_t::decode(data_buffer_t &buf)
{
    if(!header_complete) {
        if(!parse_header(buf)) {
            return false;
        }
    }

    if(header_complete && !body_complete) {
        if(!parse_body(buf)) {
            return false;
        }
    }

    return true;
}

void tmod_http_t::purge()
{
    header_complete = false;
    body_complete = false;

    client_buffer->rewind();
    server_buffer->rewind();
}

#if 0
bool tmod_http_t::decode(const uint8_t *data, uint32_t length)
{
    buffer->queue(data, length);

    return decode();
}
#endif
