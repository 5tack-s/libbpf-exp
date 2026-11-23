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
int police_deny_path(struct police *p, const char *cgroup_path);
int police_allow_path(struct police *p, const char *cgroup_path);

/* Deny an arbitrary inode number (e.g. a cgroup directory inode collected
 * from a subtree walk). */
int police_deny_inode(struct police *p, uint64_t inode);
int police_allow_inode(struct police *p, uint64_t inode);

/* Recursively deny a cgroup and every descendant cgroup directory.
 * Provides subtree inheritance so child cgroups cannot escape policing. */
int police_deny_subtree(struct police *p, const char *cgroup_path);
int police_allow_subtree(struct police *p, const char *cgroup_path);

/* Toggle audit-only mode: log violations but do not return -EPERM. */
int police_set_audit_only(struct police *p, int enabled);
