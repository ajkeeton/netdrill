#pragma once

#include "decoder.h"

class event_act_t
{
    void *user;
public:
    event_act_t() {}
    event_act_t(const char *desc);
    virtual void execute(const tmod_pkt_t &pkt) {}
};

class event_act_cb_t : public event_act_t
{
//    event_callback_t callback;
public:
};

class event_act_fork_exec_t : public event_act_t
{
    char command[8192];
    char *args[8192];
public:
    event_act_fork_exec_t() {
        sprintf(command, "echo Pattern matched but no command specified.");
    }

    event_act_fork_exec_t(const char *c) {
        set(c);
    }

    ~event_act_fork_exec_t() {
        for(uint32_t i=0; args[i]; i++)
            delete args[i];
    }

    void execute(const tmod_pkt_t &pkt);

    void set(const char *c);
};

class event_act_log_pkt : public event_act_t
{
public:
};

class event_act_log_msg : public event_act_t
{
public:
};

event_act_t *new_event_act(const char *act);

