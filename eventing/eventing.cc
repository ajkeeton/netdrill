#include <stdlib.h>
#include <errno.h>
#include <stdexcept>
#include <string.h>
#include "decoder.h"
#include "eventing.h"

tmod_event_t::tmod_event_t()
{
    conf_file = NULL;
}

tmod_event_t::tmod_event_t(char *file)
{
    conf_file = fopen(file, "r");
    
    if(!conf_file) {
        printf("Failed to open %s: %s\n", file, strerror(errno));
        throw std::runtime_error("Could not open pattern file");
    }

    parse_file(conf_file);
}

tmod_event_t::~tmod_event_t()
{
    if(conf_file)
        fclose(conf_file);
}

void base64_to_bin(uint8_t *binbuf, char *src, uint32_t buflen)
{
    printf("%s not yet available\n", __func__);
}

void hex_to_bin(
    uint8_t *binbuf, uint32_t *length, char *src, uint32_t buflen)
{
    printf("%s not yet available\n", __func__);
}

void tmod_event_t::add_raw(char *pattern, char *action)
{
    uint8_t *buf = new uint8_t[strlen(pattern)+1];

    memcpy(buf, pattern, strlen(pattern));

    /* buf[strlen(pattern)] = 0; <- don't null terminate. Using memcmp. */

    patterns.push_back(
        new event_node_raw_t(buf, strlen(pattern), new_event_act(action)));
}

void tmod_event_t::add_hex(char *pattern, char *action)
{
    uint8_t *binbuf = new uint8_t[strlen(pattern)];
    uint32_t length;

    hex_to_bin(binbuf, &length, pattern, sizeof(binbuf));

    patterns.push_back(
        new event_node_raw_t(binbuf, length, new_event_act(action)));
}

void tmod_event_t::add_regex(char *pattern, char *action)
{
    pcre *re;
    const char *error;
    int erroffset;

    if(!(re = pcre_compile(
        pattern, 0, &error, &erroffset, NULL))) {

        printf("PCRE compilation failed at %d: %s\n", 
            erroffset, error);

        throw std::runtime_error("Could not parse pattern");
    }

    pcre_extra *extra = pcre_study(re, 0, &error);

    if(!extra) {
        printf("PCRE study failed: %s\n", error);

        throw std::runtime_error("libpcre could not study pattern");
    }

    patterns.push_back(new event_node_pcre_t(re, extra, new_event_act(action)));
}

static void strip(char *buf)
{
    for(uint32_t i=strlen(buf) - 1; i >= 0 && isspace(buf[i]); i--)
        buf[i] = 0;
}

void tmod_event_t::parse_file(FILE *fd)
{
    char buf[4096];

    while(fgets(buf, sizeof(buf), fd)) {

        if(!strlen(buf) || buf[0] == '\n') continue;
        if(buf[0] == '#') continue;

        char *type = strtok(buf, ";");
        char *pattern = strtok(NULL, ";");
        char *action = strtok(NULL, ";");

        if(!pattern || !action) {
            strip(buf);
            printf("Invalid rule. Missing pattern or action: %s\n", buf);
            continue;
        }

        if(!strncmp(type, "raw", 3)) {
            add_raw(pattern, action);
        }
        else if(!strncmp(type, "hex", 3)) {
            add_hex(pattern, action);
        }
        else if(!strncmp(type, "re", 2)) {
            add_regex(pattern, action);
        }
        else {
            strip(buf);
            printf("Could not parse %s\n", buf);
        }
    }
}

event_stat_t tmod_event_t::search(const tmod_pkt_t &pkt)
{
    for(std::list<event_node_t*>::iterator it = patterns.begin();
           it != patterns.end(); it++) {
        if((*it)->match(pkt.payload, pkt.payload_size)) {
            (*it)->act(pkt);
        }
    }

    return EVENT_OK;
}

bool event_node_pcre_t::match(const uint8_t *data, uint32_t length) 
{
    if(!length) return false;

    const int ovect_size = 16;
    int ovect[ovect_size];

    int rc = pcre_exec(re, extra, (char*)data, length,
                       0, 0, ovect, ovect_size); 

    if (rc < 0) {
        if(rc == PCRE_ERROR_NOMATCH) return false;
        printf("libpcre error: %d\n", rc);
        return false;
    }

    return true;
}

bool event_node_raw_t::match(const uint8_t *data, uint32_t length) 
{
    return memmem(data, length, pattern, pattern_length);
}

event_node_raw_t::event_node_raw_t( 
    const uint8_t *pat, uint32_t length, event_act_t *act) 
{
    if(length > sizeof(pattern))
        throw std::runtime_error("Pattern is too long");

    memcpy(pattern, pat, length);
    pattern_length = length;
    action = act;
}

event_node_pcre_t::event_node_pcre_t(pcre *r, pcre_extra *e, event_act_t *a)
{
    re = r;
    extra = e;
    action = a;
}

event_node_pcre_t::~event_node_pcre_t()
{
    // XXX cleanup for re and pcre_extra?

    if(action)
        delete action;
}
