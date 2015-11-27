#pragma once

#include <stdint.h>
#include <stdio.h>
#include <pcre.h>
#include <list>

#include "actions.h"

const uint32_t MAX_PAT_LEN = 65536;

enum event_stat_t 
{
    EVENT_OK,
    EVENT_ERR
};

typedef void (*event_callback_t)(uint8_t *, void *user);

class event_node_t
{
    void *ctx;
public:
    ~event_node_t() {
        if(action)
            delete action;
    }
    virtual bool match(const uint8_t *data, uint32_t length) = 0;
    void act(const tmod_pkt_t &pkt) { action->execute(pkt); }
    event_act_t *action;
};

class event_node_pcre_t : public event_node_t
{
    pcre *re;
    pcre_extra *extra;
public:
    event_node_pcre_t(pcre *r, pcre_extra *e, event_act_t *a); 
    ~event_node_pcre_t();
    bool match(const uint8_t *data, uint32_t length);
};

class event_node_raw_t : public event_node_t
{
    uint8_t pattern[MAX_PAT_LEN];
    uint32_t pattern_length;
public:
    event_node_raw_t(const uint8_t *data, uint32_t len, event_act_t *);
    bool match(const uint8_t *data, uint32_t length);
};

class tmod_event_t
{
    FILE *conf_file;
    std::list<event_node_t *> patterns;

    void add_hex(char *pattern, char *action);
    void add_raw(char *pattern, char *action);
    void add_regex(char *pattern, char *action);
    void parse_file(FILE *fd);
public:
    tmod_event_t();
    tmod_event_t(char *file);
    ~tmod_event_t();

    event_stat_t search(
        const uint8_t *data, uint32_t length, event_callback_t callback);
    event_stat_t search(const uint8_t *data, uint32_t length);
    event_stat_t search(const tmod_pkt_t &pkt);
};

