#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

enum police_reason {
    REASON_NONE = 0,
    REASON_CGROUP = 1,
    REASON_INODE = 2,
    REASON_PID = 3,
    REASON_PATH = 4,
};

struct police_event {
    __u64 cgid;
    __u64 inode;
    __u32 pid;
    __s32 cmd;
    __u32 reason;
    char  comm[16];
};
