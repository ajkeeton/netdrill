#include "decoder_http.h"
#include "modeler.h"

static const char *path_prefix = "/tmp/tmod";
#warning "Need to create directory if doesn't exist"

void log_to_file(bool is_client, const char *name, const uint8_t *data, uint32_t length)
{
    FILE *f;
    char namefull[128];

    sprintf(namefull, "%s/%s-%s.log", path_prefix, name, is_client ? "client" : "server");

    if(!(f = fopen(namefull, "a"))) {
        // XXX err
        abort();
    }

    fwrite(data, length, 1, f);
    const static char *line_break = "\n---------\n";
    fwrite(line_break, strlen(line_break), 1, f);

    fclose(f);
}

void tmod_modeler_t::http_handler(tmod_pkt_t &pkt)
{
    tmod_http_t *http = (tmod_http_t*)pkt.ssn->data;

    if(log_only && http->header_complete && http->body_complete) {
        if(pkt.is_tcp_client_side())
            log_to_file(true, pkt.ssn->description, pkt.payload, pkt.payload_size);
        else
            log_to_file(false, pkt.ssn->description, pkt.payload, pkt.payload_size);
        
        http->purge();
    }
}

void tmod_modeler_t::update(const tmod_pkt_t &tmp)
{
    // XXX figure out what to do about this in the future;
    tmod_pkt_t *pkt = (tmod_pkt_t*)&tmp;

    if(decode_http(*pkt)) {
        http_handler(*pkt);
        return;
    }

    #if 0
    if(decode_ssl(*pkt)) {
        return;
    }
    
    if(decode_ssh(*pkt)) {
        return;
    }
    #endif

    if(pkt->ssn->protocol() == PROTO_UNKNOWN) {
        pkt->ssn->set_protocol(PROTO_UNSUPPORTED);
    }
}

