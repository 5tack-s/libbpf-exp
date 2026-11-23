#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <auditor.skel.h>
#include "auditor.h"
#include "auditor.bpf.h"
#include "socket.h"

struct auditor {
    struct auditor_bpf *skel;
    struct ring_buffer *rb;
    struct monitor *mon;
};

static int on_event(void *ctx, void *data, size_t len)
{
    const struct audit_event *e = data;
    struct monitor *mon = ctx;
    if (len < sizeof(*e))
        return 0;

    if (e->cmd == AUDIT_CMD_EXEC) {
        fprintf(stderr, "[AUDIT] EXEC pid=%u cgid=%llu comm=%.16s name=%.16s\n",
                e->pid, (unsigned long long)e->cgid, e->comm, e->name);
        fflush(stderr);

        monitor_send_audit(mon,
                           e->pid,
                           e->comm,
                           (unsigned long long)e->cgid,
                           (unsigned long long)e->inode,
                           e->cmd,
                           "EXEC",
                           e->type,
                           e->key_size,
                           e->value_size,
                           e->max_entries,
                           e->ret,
                           e->name);
    } else {
        const char *cmd_str = e->cmd == BPF_MAP_CREATE ? "MAP_CREATE" :
                              e->cmd == BPF_PROG_LOAD ? "PROG_LOAD" : "?";
        fprintf(stderr, "[AUDIT] pid=%u cgid=%llu comm=%.16s cmd=%s type=%u "
                        "key=%u val=%u max=%u ret=%lld name=%.16s\n",
                e->pid, (unsigned long long)e->cgid, e->comm, cmd_str,
                e->type, e->key_size, e->value_size, e->max_entries,
                (long long)e->ret, e->name);
        fflush(stderr);

        monitor_send_audit(mon,
                           e->pid,
                           e->comm,
                           (unsigned long long)e->cgid,
                           (unsigned long long)e->inode,
                           e->cmd,
                           cmd_str,
                           e->type,
                           e->key_size,
                           e->value_size,
                           e->max_entries,
                           e->ret,
                           e->name);
    }

    return 0;
}

struct auditor *auditor_open(void)
{
    struct auditor *a = calloc(1, sizeof(*a));
    if (!a)
        return NULL;

    a->skel = auditor_bpf__open_and_load();
    if (!a->skel) {
        int saved = errno;
        free(a);
        errno = saved;
        return NULL;
    }

    return a;
}

void auditor_close(struct auditor *a)
{
    if (!a)
        return;
    /* Destroy each program link before destroying the skeleton to ensure
     * the kernel releases the hooks and a subsequent auditor instance can
     * start with a clean policy state. */
    if (a->skel) {
        if (a->skel->links.on_bpf)
            bpf_link__destroy(a->skel->links.on_bpf);
        if (a->skel->links.out_bpf)
            bpf_link__destroy(a->skel->links.out_bpf);
        if (a->skel->links.trace_exec)
            bpf_link__destroy(a->skel->links.trace_exec);
    }
    ring_buffer__free(a->rb);
    auditor_bpf__destroy(a->skel);
    free(a);
}

int auditor_attach(struct auditor *a, struct monitor *mon)
{
    int err;

    a->mon = mon;

    err = auditor_bpf__attach(a->skel);
    if (err)
        return err;

    a->rb = ring_buffer__new(bpf_map__fd(a->skel->maps.events), on_event,
                             a->mon, NULL);
    return a->rb ? 0 : -errno;
}

int auditor_poll(struct auditor *a, int timeout_ms)
{
    if (!a || !a->rb)
        return -EINVAL;
    return ring_buffer__poll(a->rb, timeout_ms);
}
