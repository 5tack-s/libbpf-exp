#pragma once

/*
 * socket.h - Lightweight UNIX domain socket exporter/importer for libbpf-exp
 *
 * Sends newline-delimited JSON events from the eBPF ring buffer callbacks
 * to a local FastAPI middleman, which in turn streams them to a Vue frontend
 * over WebSocket.  The middleman can also send command JSON back over the
 * same socket to dynamically update deny lists (inodes, paths, audit-only).
 *
 * The socket is non-blocking: if the middleman is not connected or cannot
 * keep up, events are silently dropped so that the BPF poll loop is never
 * stalled.
 */

#ifndef LIBBPF_EXP_SOCKET_H
#define LIBBPF_EXP_SOCKET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>

struct monitor {
    int fd;
    struct sockaddr_un addr;
    int connected;
    /* Receive buffer for incoming command lines from the middleman. */
    char rx_buf[1024];
    size_t rx_len;
};

/* Path of the UNIX domain socket shared with the FastAPI middleman. */
#define MONITOR_SOCK_PATH "/tmp/libbpf-exp.sock"

/* Initialise the monitor and connect to the middleman socket.
 * Returns 0 on success, -1 on error (errno is set). */
int monitor_init(struct monitor *m);

/* Send a newline-terminated JSON payload. Non-blocking: drops the event if
 * the socket cannot accept it immediately. */
void monitor_send(struct monitor *m, const char *json);

/* Close the socket and release resources. */
void monitor_close(struct monitor *m);

/* Convenience: build and send a JSON event for a police (lsm/bpf) event. */
void monitor_send_police(struct monitor *m,
                         unsigned int pid,
                         const char *comm,
                         unsigned long long cgid,
                         unsigned long long inode,
                         int cmd,
                         const char *reason);

/* Convenience: build and send a JSON event for an auditor (kprobe/tracepoint) event. */
void monitor_send_audit(struct monitor *m,
                        unsigned int pid,
                        const char *comm,
                        unsigned long long cgid,
                        unsigned long long inode,
                        int cmd,
                        const char *cmd_str,
                        unsigned int type,
                        unsigned int key_size,
                        unsigned int value_size,
                        unsigned int max_entries,
                        long long ret,
                        const char *name);

/* Convenience: build and send a JSON command-acknowledgement event. */
void monitor_send_cmd_ack(struct monitor *m,
                          const char *action,
                          int success,
                          const char *msg);

/* Commands understood by the auditor (received from the middleman). */
enum monitor_cmd {
    MONITOR_CMD_UNKNOWN = 0,
    MONITOR_CMD_DENY_INODE,
    MONITOR_CMD_ALLOW_INODE,
    MONITOR_CMD_DENY_PATH,
    MONITOR_CMD_ALLOW_PATH,
    MONITOR_CMD_SET_AUDIT_ONLY,
};

/* Parsed representation of a command received from the middleman. */
struct monitor_cmd_req {
    enum monitor_cmd action;
    uint64_t inode;       /* for deny/allow inode */
    char path[256];       /* for deny/allow path */
    int enabled;          /* for set_audit_only */
};

/* Try to receive and parse a command from the socket.
 * Returns 1 if a command was parsed and stored in *cmd, 0 if none available,
 * -1 on error (connection lost). */
int monitor_recv_cmd(struct monitor *m, struct monitor_cmd_req *cmd);

#endif /* LIBBPF_EXP_SOCKET_H */
