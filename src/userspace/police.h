// By default everything is allowed, and we must set up the deny list.

#pragma once
#include <stdint.h>

struct monitor;
struct police;

struct police *police_open(void);
void police_close(struct police *p);
int police_attach(struct police *p, struct monitor *mon);
int police_poll(struct police *p, int timeout_ms);

int police_deny_id(struct police *p, uint64_t cgid);
int police_allow_id(struct police *p, uint64_t cgid); /* actually removes from deny list */
int police_deny_cgroup_path(struct police *p, const char *cgroup_path);
int police_allow_cgroup_path(struct police *p, const char *cgroup_path);

/* Deny an arbitrary inode number (e.g. a cgroup directory inode collected
 * from a subtree walk). */
int police_deny_inode(struct police *p, uint64_t inode);
int police_allow_inode(struct police *p, uint64_t inode);

/* Deny/allow an individual PID. This works without writing to cgroup.procs,
 * so it is reliable under WSL2 where cgroup.procs writes can fail with EBUSY. */
int police_deny_pid(struct police *p, uint32_t pid);
int police_allow_pid(struct police *p, uint32_t pid);

/* Deny/allow an executable path by its inode number.
 * The server stats the path server-side and keys the BPF denied_paths map
 * on st_ino. The BPF hook reads the caller's executable inode via
 * current->mm->exe_file->f_inode->i_ino and checks it against this map,
 * blocking any bpf() call from that executable regardless of cgroup. */
int police_deny_path(struct police *p, const char *path);
int police_allow_path(struct police *p, const char *path);

/* Recursively deny a cgroup and every descendant cgroup directory.
 * Provides subtree inheritance so child cgroups cannot escape policing. */
int police_deny_subtree(struct police *p, const char *cgroup_path);
int police_allow_subtree(struct police *p, const char *cgroup_path);

/* Toggle audit-only mode: log violations but do not return -EPERM. */
int police_set_audit_only(struct police *p, int enabled);
