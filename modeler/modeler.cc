#include "decoder_http.h"
#include "modeler.h"

static const char *path_prefix = "/tmp/tmod";
#warning "Need to create directory if doesn't exist"

void log_to_file(const char *extra, const char *name, const uint8_t *data, uint32_t length)
{
    FILE *f;
    char namefull[256];

    if(extra)
        sprintf(namefull, "%s/%s-%s.log", path_prefix, name, extra);
    else
        sprintf(namefull, "%s/%s.log", path_prefix, name);

    if(!(f = fopen(namefull, "a"))) {
        // XXX err
        abort();
    }

    fwrite(data, length, 1, f);
    const static char *line_break = "\n---------\n";
    fwrite(line_break, strlen(line_break), 1, f);

    fclose(f);
}

void log_to_file(tmod_pkt_t &pkt)
{
    tmod_http_t *http = (tmod_http_t*)pkt.ssn->data;
    http_data_buffer_t *client = http->client_buffer,
                       *server = http->server_buffer;
    
    log_to_file("client-header", pkt.ssn->description, 
        client->start() + client->header_offset,
        client->body_offset);
    log_to_file("client-body", pkt.ssn->description, 
        client->start() + client->body_offset,
        client->body_length);

    log_to_file("server-header", pkt.ssn->description,
        server->start() + server->header_offset,
        server->body_offset);
    log_to_file("server-body", pkt.ssn->description, 
        server->start() + server->body_offset,
        server->body_length);
}

void tmod_modeler_t::http_handler(tmod_pkt_t &pkt)
{
    tmod_http_t *http = (tmod_http_t*)pkt.ssn->data;

    if(log_only && 
       http->client_buffer->complete() &&
       http->server_buffer->complete()) {

        //if(foo)
            log_to_file(pkt); 
        //else
        //  log_to_db(pkt);

        http->purge();
    }
}

void tmod_modeler_t::update(const tmod_pkt_t &tmp)
{
    // XXX figure out what to do about this in the future;
    tmod_pkt_t *pkt = (tmod_pkt_t*)&tmp;

    if(pkt->ssn) {
        if(pkt->ssn->protocol() == PROTO_HTTP) {
            http_handler(*pkt);
        }
        // else if ssh ...
        // else if tls ...
    }

    if(pkt->ssn->protocol() == PROTO_UNKNOWN) {
        pkt->ssn->set_protocol(PROTO_UNSUPPORTED);
    }
}

