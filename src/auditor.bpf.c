// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

//https://github.com/libbpf/libbpf-bootstrap
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "auditor.bpf.h"

#define EPERM  1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); //1 MiB
} events SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct audit_event);
} inflight SEC(".maps");


SEC("ksyscall/bpf")
int BPF_KSYSCALL(on_bpf, int cmd, union bpf_attr *uattr, unsigned int size){
    if(cmd != BPF_MAP_CREATE && cmd != BPF_PROG_LOAD)
        return 0;

    union bpf_attr attr = {};
    struct audit_event e = {};
    u64 id = bpf_get_current_pid_tgid();
    
    // u32 sz = size < sizeof(attr) ? size :sizeof(attr);
    u64 sz = size;
    if(sz > sizeof(attr))
        sz = sizeof(attr);

    barrier_var(sz);
    if(sz > sizeof(attr))
        return 0;
    if(bpf_probe_read_user(&attr, sz, uattr)) //failure to read means early return
        return 0;
    
    e.pid = id >> 32;
    e.cmd = cmd;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    if(cmd == BPF_MAP_CREATE){
        e.type = attr.map_type;
        e.key_size = attr.key_size;
        e.value_size = attr.value_size;
        e.max_entries = attr.max_entries;
        __builtin_memcpy(e.name, attr.map_name, sizeof(e.name));
    }
    else{ //BPF_PROG_LOAD
        e.type = attr.prog_type;
        __builtin_memcpy(e.name, attr.prog_name, sizeof(e.name));
    }

    bpf_map_update_elem(&inflight, &id, &e, BPF_ANY);
    return 0;
}

SEC("kretsyscall/bpf")
int BPF_KRETPROBE(out_bpf, long ret){
    u64 id = bpf_get_current_pid_tgid();
    struct audit_event *e = bpf_map_lookup_elem(&inflight, &id);

    if(!e)
        return 0;

    e->ret = ret;
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    bpf_map_delete_elem(&inflight, &id);
    return 0;

}