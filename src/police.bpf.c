#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "police.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u64);
    __type(value, u8);
} denied_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); //256 KiB   
} events SEC(".maps");

SEC("lsm/bpf")
int BPF_PROG(police_bpf, int cmd, union bpf_attr *attr, unsigned int size, bool kernel, int ret){

    if(ret)
        return ret;

    if(cmd != BPF_MAP_CREATE && cmd != BPF_PROG_LOAD)
        return 0;

    u64 cgid = bpf_get_current_cgroup_id();
    if(!bpf_map_lookup_elem(&denied_cgroups, &cgid))
        return 0;

//    bpf_printk("[POLICE] DENIED cmd=%d cgroup=%llu", cmd, cgid);
    struct police_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->cgid = cgid;
        e->pid  = bpf_get_current_pid_tgid() >> 32;
        e->cmd  = cmd;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
return -EPERM;
}
