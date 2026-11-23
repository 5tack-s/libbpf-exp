#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "police.h"
#include "auditor.h"
#include "socket.h"

static volatile sig_atomic_t exit_requested = 0;

static void sig_handler(int sig)
{
    (void)sig;
    exit_requested = 1;
}

static void setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    /* Do not restart interrupted syscalls so poll() returns -EINTR
     * promptly on SIGINT/SIGTERM, allowing the process to exit and
     * detach its BPF programs. */
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] <cgroup_path>\n"
        "\n"
        "eBPF process monitor and policing tool. Matches blacklisted cgroup\n"
        "inodes (and arbitrary inodes) from running BPF functions.\n"
        "\n"
        "Options:\n"
        "  -a, --audit-only    Log violations but do not enforce (-EPERM)\n"
        "  -c, --cgroup PATH   Cgroup path to deny (default: /sys/fs/cgroup/denied)\n"
        "  -S, --no-subtree    Do not deny descendant cgroups (exact match only)\n"
        "  -l, --log FILE      Write logs to FILE instead of stderr\n"
        "  -v, --verbose       Enable libbpf debug output\n"
        "  -h, --help          Show this help\n"
        "\n"
        "Examples:\n"
        "  sudo %s /sys/fs/cgroup/denied\n"
        "  sudo %s -a -c /sys/fs/cgroup/untrusted\n",
        prog, prog, prog);
}

/* Handle a command received from the middleman over the UNIX socket.
 * Dispatches to the appropriate police_* function and sends a CMD_ACK
 * back to the frontend. */
static int handle_monitor_cmd(struct police *p, struct monitor *mon,
                              const struct monitor_cmd_req *cmd)
{
    int err = 0;
    int success = 1;
    const char *msg = "ok";
    char msg_buf[128];

    switch (cmd->action) {
    case MONITOR_CMD_DENY_INODE:
        err = police_deny_inode(p, cmd->inode);
        if (err) {
            success = 0;
            snprintf(msg_buf, sizeof(msg_buf), "deny_inode failed: %s", strerror(-err));
            msg = msg_buf;
        } else {
            fprintf(stderr, "[INFO] denied inode %llu via web command\n",
                    (unsigned long long)cmd->inode);
        }
        break;
    case MONITOR_CMD_ALLOW_INODE:
        err = police_allow_inode(p, cmd->inode);
        if (err) {
            success = 0;
            snprintf(msg_buf, sizeof(msg_buf), "allow_inode failed: %s", strerror(-err));
            msg = msg_buf;
        } else {
            fprintf(stderr, "[INFO] allowed inode %llu via web command\n",
                    (unsigned long long)cmd->inode);
        }
        break;
    case MONITOR_CMD_DENY_PATH:
        err = police_deny_path(p, cmd->path);
        if (err) {
            success = 0;
            snprintf(msg_buf, sizeof(msg_buf), "deny_path failed: %s", strerror(-err));
            msg = msg_buf;
        } else {
            fprintf(stderr, "[INFO] denied path %s via web command\n", cmd->path);
        }
        break;
    case MONITOR_CMD_ALLOW_PATH:
        err = police_allow_path(p, cmd->path);
        if (err) {
            success = 0;
            snprintf(msg_buf, sizeof(msg_buf), "allow_path failed: %s", strerror(-err));
            msg = msg_buf;
        } else {
            fprintf(stderr, "[INFO] allowed path %s via web command\n", cmd->path);
        }
        break;
    case MONITOR_CMD_DENY_PID:
        err = police_deny_pid(p, cmd->pid);
        if (err) {
            success = 0;
            snprintf(msg_buf, sizeof(msg_buf), "deny_pid failed: %s", strerror(-err));
            msg = msg_buf;
        } else {
            fprintf(stderr, "[INFO] denied pid %u via web command\n", cmd->pid);
        }
        break;
    case MONITOR_CMD_ALLOW_PID:
        err = police_allow_pid(p, cmd->pid);
        if (err) {
            success = 0;
            snprintf(msg_buf, sizeof(msg_buf), "allow_pid failed: %s", strerror(-err));
            msg = msg_buf;
        } else {
            fprintf(stderr, "[INFO] allowed pid %u via web command\n", cmd->pid);
        }
        break;
    case MONITOR_CMD_SET_AUDIT_ONLY:
        err = police_set_audit_only(p, cmd->enabled);
        if (err) {
            success = 0;
            snprintf(msg_buf, sizeof(msg_buf), "set_audit_only failed: %s", strerror(-err));
            msg = msg_buf;
        } else {
            fprintf(stderr, "[INFO] audit-only set to %d via web command\n", cmd->enabled);
        }
        break;
    case MONITOR_CMD_UNKNOWN:
    default:
        success = 0;
        msg = "unknown command";
        break;
    }

    monitor_send_cmd_ack(mon,
                         cmd->action == MONITOR_CMD_DENY_INODE   ? "deny_inode" :
                         cmd->action == MONITOR_CMD_ALLOW_INODE  ? "allow_inode" :
                         cmd->action == MONITOR_CMD_DENY_PATH    ? "deny_path" :
                         cmd->action == MONITOR_CMD_ALLOW_PATH   ? "allow_path" :
                         cmd->action == MONITOR_CMD_DENY_PID     ? "deny_pid" :
                         cmd->action == MONITOR_CMD_ALLOW_PID    ? "allow_pid" :
                         cmd->action == MONITOR_CMD_SET_AUDIT_ONLY ? "set_audit_only" :
                                                                   "unknown",
                         success, msg);
    return err;
}

int main(int argc, char **argv)
{
    static struct option long_opts[] = {
        {"audit-only", no_argument, NULL, 'a'},
        {"cgroup", required_argument, NULL, 'c'},
        {"no-subtree", no_argument, NULL, 'S'},
        {"log", required_argument, NULL, 'l'},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };

    const char *cgroup_path = "/sys/fs/cgroup/denied";
    int audit_only = 0;
    int deny_subtree = 1;
    const char *log_file = NULL;
    int verbose = 0;
    int opt;

    while ((opt = getopt_long(argc, argv, "ac:Sl:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'a':
            audit_only = 1;
            break;
        case 'c':
            cgroup_path = optarg;
            break;
        case 'S':
            deny_subtree = 0;
            break;
        case 'l':
            log_file = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (log_file) {
        if (freopen(log_file, "a", stderr) == NULL) {
            fprintf(stderr, "Failed to open log file %s: %s\n", log_file, strerror(errno));
            return 1;
        }
    }

    libbpf_set_print(verbose ? libbpf_print_fn : NULL);
    setup_signals();

    /* Make stderr unbuffered so logs appear immediately even when
     * stdout/stderr are redirected to files or pipes. */
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    struct police *p = NULL;
    struct auditor *a = NULL;
    struct monitor mon;
    int err;
    int rc = 1;

    /* Initialise the socket exporter to the FastAPI middleman. If the
     * middleman is not running, events are dropped silently and the auditor
     * continues to work in standalone mode. Retry the connection a few times
     * so that a briefly-unavailable middleman doesn't leave the auditor
     * permanently disconnected. */
    if (monitor_init(&mon) != 0) {
        fprintf(stderr, "[WARN] Failed to initialise monitor socket: %s\n",
                strerror(errno));
    }
    for (int tries = 0; tries < 10 && !mon.connected; tries++) {
        usleep(200000); /* 200 ms */
        if (monitor_init(&mon) != 0)
            continue;
    }
    if (!mon.connected)
        fprintf(stderr, "[WARN] Middleman not reachable; running standalone\n");

    p = police_open();
    if (!p) {
        fprintf(stderr, "[FATAL] Failed to load police: %s\n", strerror(errno));
        monitor_close(&mon);
        goto out;
    }

    a = auditor_open();
    if (!a) {
        fprintf(stderr, "[FATAL] Failed to load auditor: %s\n", strerror(errno));
        police_close(p);
        monitor_close(&mon);
        goto out;
    }

    err = police_attach(p, &mon);
    if (err) {
        fprintf(stderr, "[FATAL] Failed to attach police: %s\n", strerror(-err));
        police_close(p);
        auditor_close(a);
        monitor_close(&mon);
        goto out;
    }

    err = auditor_attach(a, &mon);
    if (err) {
        fprintf(stderr, "[FATAL] Failed to attach auditor: %s\n", strerror(-err));
        police_close(p);
        auditor_close(a);
        monitor_close(&mon);
        goto out;
    }

    /* Apply audit-only toggle before inserting deny rules so the BPF
     * program behaves consistently from the start. */
    err = police_set_audit_only(p, audit_only);
    if (err) {
        fprintf(stderr, "[WARN] Failed to set audit-only mode: %s\n", strerror(-err));
    }

    /* Ensure the cgroup directory exists. If it doesn't, create it so the
     * subsequent deny_path/deny_subtree stat() calls succeed. */
    if (mkdir(cgroup_path, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "[FATAL] Failed to create cgroup directory %s: %s\n",
                cgroup_path, strerror(errno));
        goto out;
    }

    if (deny_subtree)
        err = police_deny_subtree(p, cgroup_path);
    else
        err = police_deny_cgroup_path(p, cgroup_path);

    if (err) {
        fprintf(stderr, "[FATAL] Failed to deny %s: %s\n",
                cgroup_path, strerror(-err));
        goto out;
    }

    fprintf(stderr, "[INFO] auditor: policing cgroup %s (subtree=%d, audit_only=%d)\n",
            cgroup_path, deny_subtree, audit_only);

    while (!exit_requested) {
        /* Block on police events for up to 500 ms. */
        err = police_poll(p, 500);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "police poll: %s\n", strerror(-err));
            goto out;
        }

        /* Drain all currently available auditor events without blocking. */
        while ((err = auditor_poll(a, 0)) > 0)
            ;
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "auditor poll: %s\n", strerror(-err));
            goto out;
        }

        /* Drain commands from the middleman (deny/allow path,
         * set_audit_only) and apply them to the police BPF maps. */
        {
            struct monitor_cmd_req req;
            while ((err = monitor_recv_cmd(&mon, &req)) > 0)
                handle_monitor_cmd(p, &mon, &req);
            if (err < 0) {
                /* Connection lost; try to reconnect to the middleman so
                 * web commands (deny/allow path) keep working. Events
                 * continue to be emitted to stderr even if the middleman
                 * is unreachable. */
                fprintf(stderr, "[WARN] monitor connection lost; reconnecting...\n");
                if (mon.fd >= 0) {
                    close(mon.fd);
                    mon.fd = -1;
                }
                mon.connected = 0;
                for (int tries = 0; tries < 30 && !exit_requested; tries++) {
                    if (monitor_init(&mon) == 0 && mon.connected) {
                        fprintf(stderr, "[INFO] monitor reconnected\n");
                        break;
                    }
                    fprintf(stderr, "[WARN] reconnect attempt %d failed, retrying...\n", tries + 1);
                    sleep(1);
                }
            }
        }
    }

    rc = 0;

out:
    police_close(p);
    auditor_close(a);
    monitor_close(&mon);
    return rc;
}
