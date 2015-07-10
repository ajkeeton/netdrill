#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include "logger.h"
#include "actions.h"

event_act_t::event_act_t(const char *act)
{
}

event_act_t *new_event_act(const char *act)
{
    if(!act) return NULL;

    if(!strncmp(act, "exec", 4)) {
        return new event_act_fork_exec_t(act + 5);
    }
    //else if(!strncmp(act, "log_session", strlen("log_session"))) {
    //    return new event_act_log_session_t();
    //}
    else {
        return new event_act_t();
    }
}

void event_act_free_environ(char **p)
{
}

char **event_act_alloc_environ(const tmod_pkt_t &pkt)
{
    char **envp = new char*[4];

    envp[0] = new char[1024];
    sprintf(envp[0], "TMOD_TIME=%u", time(NULL));

    char srcip[128], dstip[128];
    inet_ntop(AF_INET, &pkt.iph.rawiph->src, srcip, sizeof(srcip));
    inet_ntop(AF_INET, &pkt.iph.rawiph->dst, dstip, sizeof(dstip));

    char session_desc[256];
    sprintf(session_desc, "%s:%d -> %s:%d", 
        srcip, pkt.tcph.rawtcp->src_port, 
        dstip, pkt.tcph.rawtcp->dst_port);

    envp[1] = new char[1024];
    sprintf(envp[1], "TMOD_SESSION=%s", session_desc);

    char hex_str[pkt.payload_size * 6];  /* 6 is an estimate */
    envp[2] = new char[pkt.payload_size * 6];  /* 6 is an estimate */
    tmod_hex_dump(hex_str, sizeof(hex_str), pkt.payload, pkt.payload_size);

    snprintf(envp[2], pkt.payload_size * 6, "TMOD_HEX_PAYLOAD=%s", hex_str);

    envp[3] = NULL;

    return envp;
}

void event_act_fork_exec_t::execute(const tmod_pkt_t &pkt)
{
    int status;
    char **envp = event_act_alloc_environ(pkt);
    pid_t pid = fork();

    if (pid < 0) {
        // XXX Error
        exit(-1);
    }

    if (pid > 0) {
        if(waitpid(pid, &status, 0) < 0) {
            printf("waitpid err: %s\n", strerror(errno));
        }

        return;
    }

    status = execve(command, args, envp);

    if(status < 0) 
        printf("Error executing %s: %s\n", command, strerror(errno));

    /* Technically this memory is cleaned up anyway */
    event_act_free_environ(envp);    

    exit(status);
}

void event_act_fork_exec_t::set(const char *c)
{
    char *s = strtok((char*)c, " ");

    if(s) {
        strcpy(command, s);

        int i = strlen(command) - 1;

        while(isspace(command[i])) {
            command[i--] = 0;
        }
    }

    args[0] = new char[strlen(command)];
    strcpy(args[0], command);

    uint32_t i = 1;

    while((s = strtok(NULL, " "))) {
        args[i] = new char[strlen(s)];
        strcpy(args[i++], s);
    }

    args[i] = NULL;
}

