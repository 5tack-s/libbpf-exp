// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

//https://github.com/libbpf/libbpf-bootstrap
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <auditor.skel.h>
#include "auditor.h"
#include "auditor.bpf.h"
struct auditor {
    struct auditor_bpf *skel;
    struct ring_buffer *rb;
};

static int on_event(void *ctx, void *data, size_t len){
    const struct audit_event *e = data;
    if(len < sizeof(*e))
        return 0;
    fprintf(stderr, "[AUDIT] pid=%u, comm=%.16s cmd=%u, type=%u, name=%.16s ret=%lld\n", 
    e->pid, e->comm, e->cmd, e->type, e->name, (long long)e->ret
    );

    return 0;
}

struct auditor *auditor_open(void){
    struct auditor *a = calloc(1, sizeof(*a));
    if(!a) return NULL;

    a->skel = auditor_bpf__open_and_load();
    if(!a->skel){
        int saved = errno;
        free(a);
        errno = saved;
        return NULL;
    }

    return a;
}

void auditor_close(struct auditor *a){
    if(!a) return;
    ring_buffer__free(a->rb);
    auditor_bpf__destroy(a->skel);
    free(a);
}

//0: Success
//1 or <0: -errno
int auditor_attach(struct auditor *a){
   int err = auditor_bpf__attach(a->skel);
    if(err)
        return err;

    a->rb = ring_buffer__new(bpf_map__fd(a->skel->maps.events), on_event, NULL, NULL);
    return a->rb ? 0 : -errno;
}

int auditor_poll(struct auditor *a, int timeout_ms){
    if(!a || !a->rb)
        return -EINVAL;
    return ring_buffer__poll(a->rb, timeout_ms);
}
