#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif


struct police_event {
    __u64 cgid;
    __u32 pid;
    __s32 cmd;
    char  comm[16];
};
