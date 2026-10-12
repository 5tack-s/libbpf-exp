#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <police.skel.h>
#include "police.h"
#include "police.bpf.h"

struct police {
    struct police_bpf *skel;
    struct ring_buffer *rb;  
};

static int on_event(void *ctx, void *data, size_t len){
    const struct police_event *e = data;
    if(len < sizeof(*e))
        return 0;
    printf("[POLICE] DENIED cmd=%d pid=%u comm=%.16s cgroup=%llu\n",
           e->cmd, e->pid, e->comm, (unsigned long long)e->cgid);
    return 0;
}


struct police *police_open(void){
    struct police *p = calloc(1, sizeof(*p));
    if(!p)
        return NULL;

    p->skel = police_bpf__open_and_load();
    if(!p->skel){
        int saved = errno;
        free(p);
        errno = saved;
        return NULL;
    }
    return p;
}

void police_close(struct police *p){
    if(!p) return;
    ring_buffer__free(p->rb);
    police_bpf__destroy(p->skel);
    free(p);
}

int police_attach(struct police *p){
    int err = police_bpf__attach(p->skel);
    if(err)
        return err;

    p->rb = ring_buffer__new(bpf_map__fd(p->skel->maps.events), on_event, NULL, NULL);
    return p->rb ? 0 : -errno;
}

int police_poll(struct police *p, int timeout_ms){
    if(!p || !p->rb)
        return -EINVAL;
    return ring_buffer__poll(p->rb, timeout_ms);
}

static int path_to_id(const char *path, uint64_t *id){
    struct stat st;

    if(stat(path, &st)){
        return -errno;
    }

    if(!S_ISDIR(st.st_mode))
        return -ENOTDIR;

    *id = st.st_ino;
    return 0;
}

int police_deny_id(struct police *p, uint64_t cgid){
    
    uint8_t one = 1;

    return bpf_map__update_elem(
        p->skel->maps.denied_cgroups,
        &cgid,
        sizeof(cgid),
        &one,
        sizeof(one),
        BPF_ANY
    );
}

int police_allow_id(struct police *p, uint64_t cgid){
    return bpf_map__delete_elem(p->skel->maps.denied_cgroups, 
    &cgid,
    sizeof(cgid),
    0
    );
}

int police_deny_path(struct police *p, const char *path){
    uint64_t id;
    int err = path_to_id(path, &id);
    return err ? err : police_deny_id(p, id);
}

int police_allow_path(struct police *p, const char *path){
    uint64_t id;
    int err = path_to_id(path, &id);

    return err ? err : police_allow_id(p, id);
}
