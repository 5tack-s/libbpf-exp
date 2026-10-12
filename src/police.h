//by default everything is allowed, and we must set up the deny list

#pragma once
#include <stdint.h>

struct police;

struct police *police_open(void);
void police_close(struct police *p);
int police_attach(struct police *p);
int police_poll(struct police *p, int timeout_ms);

int police_deny_id(struct police *p, uint64_t cgid);
int police_allow_id(struct police *p, uint64_t cgid); //actually removes from deny list.
int police_deny_path(struct police *p, const char *cgroup_path);
int police_allow_path(struct police *p, const char *cgroup_path);

