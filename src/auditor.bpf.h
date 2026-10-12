#pragma once

#ifndef __VMLINUX_H__ 
#include <linux/types.h>
#endif

struct audit_event {
    __u32 pid;
    __u32 cmd;   
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __s64 ret;
    char comm[16];
    char name[16];
};