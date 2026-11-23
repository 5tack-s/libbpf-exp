#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "police.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, u8);
} denied_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, u8);
} denied_inodes SEC(".maps");

/* config[0]: 0 = enforce (deny), 1 = audit-only (log but allow) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} police_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KiB */
} events SEC(".maps");

SEC("lsm/bpf")
int BPF_PROG(police_bpf, int cmd, union bpf_attr *attr, unsigned int size, bool kernel, int ret)
{
    u32 key = 0;
    u32 *audit_only;
    u64 cgid;
    struct police_event *e;

    if (ret)
        return ret;

    /* Only police the operations that create or load BPF objects. */
    if (cmd != BPF_MAP_CREATE && cmd != BPF_PROG_LOAD)
        return 0;

    audit_only = bpf_map_lookup_elem(&police_config, &key);

    cgid = bpf_get_current_cgroup_id();

    /* --- Cgroup inode deny list --- */
    if (bpf_map_lookup_elem(&denied_cgroups, &cgid)) {
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->cgid = cgid;
            e->inode = cgid; /* cgroup v2 id acts as the directory inode */
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->cmd = cmd;
            e->reason = REASON_CGROUP;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
        if (!audit_only || !*audit_only)
            return -EPERM;
        return 0;
    }

    /* --- Generic inode deny list (extensible) --- */
    /* Userspace can populate denied_inodes with arbitrary inode numbers.
     * The current LSM/bpf hook does not expose a file path for
     * BPF_MAP_CREATE / BPF_PROG_LOAD, so this map is wired to the
     * cgroup id for now. Future hooks (file_alloc, mmap_file, etc.)
     * can check the real file inode here. */
    if (bpf_map_lookup_elem(&denied_inodes, &cgid)) {
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->cgid = cgid;
            e->inode = cgid;
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->cmd = cmd;
            e->reason = REASON_INODE;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
        if (!audit_only || !*audit_only)
            return -EPERM;
        return 0;
    }

    return 0;
}
