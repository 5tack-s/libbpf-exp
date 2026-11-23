#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

enum audit_cmd {
    AUDIT_CMD_BPF = 0,
    AUDIT_CMD_EXEC = 1,
};

struct audit_event {
    __u32 pid;
    __u32 cmd;     /* bpf() command or AUDIT_CMD_* */
    __u32 type;    /* map_type / prog_type for bpf; unused for exec */
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __s64 ret;
    __u64 cgid;    /* cgroup v2 id of the caller */
    __u64 inode;   /* inode associated with the event (cgroup dir inode) */
    char comm[16];
    char name[16]; /* map_name / prog_name / comm (truncated to 15 chars) */
};
