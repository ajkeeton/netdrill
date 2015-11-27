#include "ahocorasick.h"
#include "decoder_http.h"

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

bool decode_http(tmod_pkt_t &pkt) 
{ 
    return false; 
}
