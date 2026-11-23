#include "socket.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static long long now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* Extract the JSON string value for a given key from a flat JSON object.
 * Looks for "key":"value" (with optional spaces). Copies the unescaped value
 * into out. Returns 0 on success, -1 if the key is not found. */
static int json_get_str(const char *json, const char *key, char *out, size_t out_size)
{
    char search[64];
    const char *p, *val_start, *val_end;
    size_t keylen = strlen(key);

    if (keylen + 4 > sizeof(search))
        return -1;

    snprintf(search, sizeof(search), "\"%s\":", key);

    p = strstr(json, search);
    if (!p)
        return -1;

    p += strlen(search);
    /* Skip whitespace. */
    while (*p == ' ' || *p == '\t')
        p++;

    if (*p != '"')
        return -1;

    p++; /* skip opening quote */
    val_start = p;

    /* Scan to the closing quote, honoring backslash escapes. */
    while (*p && *p != '"') {
        if (*p == '\\' && p[1])
            p += 2;
        else
            p++;
    }
    val_end = p;

    if ((size_t)(val_end - val_start) >= out_size)
        return -1;

    size_t i, j = 0;
    for (i = 0; val_start + i < val_end && j + 1 < out_size; i++) {
        char c = val_start[i];
        if (c == '\\' && i + 1 < (size_t)(val_end - val_start)) {
            char n = val_start[i + 1];
            if (n == '"' || n == '\\') {
                out[j++] = n;
                i++;
            } else {
                out[j++] = c;
            }
        } else {
            out[j++] = c;
        }
    }
    out[j] = '\0';
    return 0;
}

/* Extract the JSON integer value for a given key from a flat JSON object.
 * Looks for "key":number. Returns 0 on success, -1 if the key is not found. */
static int json_get_int(const char *json, const char *key, long long *out)
{
    char search[64];
    const char *p, *val_start;
    size_t keylen = strlen(key);

    if (keylen + 4 > sizeof(search))
        return -1;

    snprintf(search, sizeof(search), "\"%s\":", key);

    p = strstr(json, search);
    if (!p)
        return -1;

    p += strlen(search);
    while (*p == ' ' || *p == '\t')
        p++;

    val_start = p;
    char *end = NULL;
    long long v = strtoll(val_start, &end, 10);
    if (end == val_start)
        return -1;

    *out = v;
    return 0;
}

int monitor_init(struct monitor *m)
{
    if (!m)
        return -1;

    m->fd = -1;
    m->connected = 0;
    m->rx_len = 0;
    memset(m->rx_buf, 0, sizeof(m->rx_buf));
    memset(&m->addr, 0, sizeof(m->addr));

    m->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m->fd < 0) {
        perror("socket");
        return -1;
    }

    m->addr.sun_family = AF_UNIX;
    snprintf(m->addr.sun_path, sizeof(m->addr.sun_path), "%s", MONITOR_SOCK_PATH);

    if (connect(m->fd, (struct sockaddr *)&m->addr, sizeof(m->addr)) < 0) {
        if (errno == EINPROGRESS) {
            /* Non-blocking connect in progress; wait for it to complete so
             * that we know for certain whether the middleman is accepting. */
            struct pollfd pfd;
            pfd.fd = m->fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            int pr = poll(&pfd, 1, 2000); /* 2 second timeout */
            if (pr > 0 && (pfd.revents & POLLOUT)) {
                m->connected = 1;
            } else {
                m->connected = 0;
                if (pr == 0)
                    fprintf(stderr, "[WARN] monitor connect timed out\n");
            }
        } else {
            /* Server not yet running; keep the socket open and retry sending
             * later. The send() will fail with ENOTCONN/EAGAIN and drop. */
            m->connected = 0;
        }
    } else {
        m->connected = 1;
    }

    return 0;
}

void monitor_send(struct monitor *m, const char *json)
{
    size_t len;
    ssize_t n;

    if (!m || m->fd < 0 || !json)
        return;

    len = strlen(json);
    if (len == 0)
        return;

    n = send(m->fd, json, len, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Transient: socket buffer full, try again later. */
            return;
        }
        /* Any other error (EPIPE, ECONNREFUSED, ENOTCONN, ...) means the
         * connection is dead. Close and mark disconnected so that
         * monitor_recv_cmd() will return -1 and trigger reconnection. */
        fprintf(stderr, "[DEBUG] monitor_send failed: %s (fd=%d, connected=%d)\n",
                strerror(errno), m->fd, m->connected);
        close(m->fd);
        m->fd = -1;
        m->connected = 0;
        return;
    }
}

void monitor_close(struct monitor *m)
{
    if (!m)
        return;
    if (m->fd >= 0) {
        close(m->fd);
        m->fd = -1;
    }
    m->connected = 0;
}

/* Minimal JSON string escaping: only quotes and backslashes need escaping
 * for the short fixed-size fields we handle (comm, name, reason, cmd_str). */
static size_t json_escape(char *dst, size_t dst_size, const char *src)
{
    size_t i, j = 0;
    for (i = 0; src[i] != '\0' && j + 1 < dst_size; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_size)
                break;
            dst[j++] = '\\';
            dst[j++] = c;
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
    return j;
}

void monitor_send_police(struct monitor *m,
                         unsigned int pid,
                         const char *comm,
                         unsigned long long cgid,
                         unsigned long long inode,
                         int cmd,
                         const char *reason)
{
    char buf[512];
    char esc_comm[32];
    char esc_reason[32];
    size_t n;

    json_escape(esc_comm, sizeof(esc_comm), comm ? comm : "");
    json_escape(esc_reason, sizeof(esc_reason), reason ? reason : "unknown");

    n = snprintf(buf, sizeof(buf),
        "{\"ts_ms\":%lld,\"type\":\"POLICE\",\"pid\":%u,\"comm\":\"%s\","
        "\"cgid\":%llu,\"inode\":%llu,\"cmd\":%d,\"reason\":\"%s\"}\n",
        now_ms(), pid, esc_comm, cgid, inode, cmd, esc_reason);

    if (n > 0 && (size_t)n < sizeof(buf))
        monitor_send(m, buf);
}

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
                        const char *name)
{
    char buf[768];
    char esc_comm[32];
    char esc_cmd[32];
    char esc_name[32];
    size_t n;

    json_escape(esc_comm, sizeof(esc_comm), comm ? comm : "");
    json_escape(esc_cmd, sizeof(esc_cmd), cmd_str ? cmd_str : "?");
    json_escape(esc_name, sizeof(esc_name), name ? name : "");

    n = snprintf(buf, sizeof(buf),
        "{\"ts_ms\":%lld,\"type\":\"AUDIT\",\"pid\":%u,\"comm\":\"%s\","
        "\"cgid\":%llu,\"inode\":%llu,\"cmd\":%d,\"cmd_str\":\"%s\","
        "\"bpf_type\":%u,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,"
        "\"ret\":%lld,\"name\":\"%s\"}\n",
        now_ms(), pid, esc_comm, cgid, inode, cmd, esc_cmd,
        type, key_size, value_size, max_entries, ret, esc_name);

    if (n > 0 && (size_t)n < sizeof(buf))
        monitor_send(m, buf);
}

void monitor_send_cmd_ack(struct monitor *m,
                          const char *action,
                          int success,
                          const char *msg)
{
    char buf[256];
    char esc_msg[64];
    char esc_action[32];
    size_t n;

    json_escape(esc_msg, sizeof(esc_msg), msg ? msg : "");
    json_escape(esc_action, sizeof(esc_action), action ? action : "unknown");

    n = snprintf(buf, sizeof(buf),
        "{\"ts_ms\":%lld,\"type\":\"CMD_ACK\",\"action\":\"%s\","
        "\"success\":%d,\"msg\":\"%s\"}\n",
        now_ms(), esc_action, success, esc_msg);

    if (n > 0 && (size_t)n < sizeof(buf))
        monitor_send(m, buf);
}

int monitor_recv_cmd(struct monitor *m, struct monitor_cmd_req *cmd)
{
    ssize_t n;
    char *line_start;
    char *newline;

    if (!m || !cmd || m->fd < 0)
        return -1;

    /* Check if data is available without blocking. */
    {
        struct pollfd pfd;
        pfd.fd = m->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        if (poll(&pfd, 1, 0) <= 0 || !(pfd.revents & POLLIN))
            return 0; /* no data available */
    }

    /* Receive available data into the buffer. */
    n = recv(m->fd, m->rx_buf + m->rx_len,
             sizeof(m->rx_buf) - 1 - m->rx_len, MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        /* Connection error. */
        return -1;
    }
    if (n == 0) {
        /* Peer closed the connection. */
        return -1;
    }

    m->rx_len += (size_t)n;
    m->rx_buf[m->rx_len] = '\0';

    /* Process complete newline-terminated lines. */
    while ((newline = strchr(m->rx_buf, '\n')) != NULL) {
        *newline = '\0';
        line_start = m->rx_buf;

        /* Skip empty lines. */
        if (strlen(line_start) > 0) {
            long long inode_val = 0;
            long long enabled_val = 0;
            char path_val[256] = {0};
            char action_str[32] = {0};
            int parsed = 0;

            if (json_get_str(line_start, "action", action_str, sizeof(action_str)) == 0) {
                parsed = 1;

                if (strcmp(action_str, "deny_inode") == 0) {
                    cmd->action = MONITOR_CMD_DENY_INODE;
                    if (json_get_int(line_start, "inode", &inode_val) == 0)
                        cmd->inode = (uint64_t)inode_val;
                } else if (strcmp(action_str, "allow_inode") == 0) {
                    cmd->action = MONITOR_CMD_ALLOW_INODE;
                    if (json_get_int(line_start, "inode", &inode_val) == 0)
                        cmd->inode = (uint64_t)inode_val;
                } else if (strcmp(action_str, "deny_path") == 0) {
                    cmd->action = MONITOR_CMD_DENY_PATH;
                    if (json_get_str(line_start, "path", path_val, sizeof(path_val)) == 0)
                        strncpy(cmd->path, path_val, sizeof(cmd->path) - 1);
                } else if (strcmp(action_str, "allow_path") == 0) {
                    cmd->action = MONITOR_CMD_ALLOW_PATH;
                    if (json_get_str(line_start, "path", path_val, sizeof(path_val)) == 0)
                        strncpy(cmd->path, path_val, sizeof(cmd->path) - 1);
                } else if (strcmp(action_str, "deny_pid") == 0) {
                    cmd->action = MONITOR_CMD_DENY_PID;
                    if (json_get_int(line_start, "pid", &inode_val) == 0)
                        cmd->pid = (uint32_t)inode_val;
                } else if (strcmp(action_str, "allow_pid") == 0) {
                    cmd->action = MONITOR_CMD_ALLOW_PID;
                    if (json_get_int(line_start, "pid", &inode_val) == 0)
                        cmd->pid = (uint32_t)inode_val;
                } else if (strcmp(action_str, "set_audit_only") == 0) {
                    cmd->action = MONITOR_CMD_SET_AUDIT_ONLY;
                    if (json_get_int(line_start, "enabled", &enabled_val) == 0)
                        cmd->enabled = (int)enabled_val;
                } else {
                    cmd->action = MONITOR_CMD_UNKNOWN;
                }
            }

            if (parsed) {
                /* Shift remaining data to the front of the buffer. */
                size_t remaining = strlen(newline + 1);
                memmove(m->rx_buf, newline + 1, remaining + 1);
                m->rx_len = remaining;
                return 1;
            }
        }

        /* Shift remaining data to the front of the buffer. */
        size_t remaining = strlen(newline + 1);
        memmove(m->rx_buf, newline + 1, remaining + 1);
        m->rx_len = remaining;
    }

    /* If buffer is full but no newline found, reset to avoid overflow. */
    if (m->rx_len >= sizeof(m->rx_buf) - 1) {
        m->rx_len = 0;
        memset(m->rx_buf, 0, sizeof(m->rx_buf));
    }

    return 0;
}
