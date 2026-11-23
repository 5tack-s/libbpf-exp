#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <police.skel.h>
#include "police.h"
#include "police.bpf.h"
#include "socket.h"

struct police {
    struct police_bpf *skel;
    struct ring_buffer *rb;
    struct monitor *mon;
};

static int on_event(void *ctx, void *data, size_t len)
{
    const struct police_event *e = data;
    struct monitor *mon = ctx;
    if (len < sizeof(*e))
        return 0;
    const char *reason_str = e->reason == REASON_CGROUP ? "cgroup" :
                             e->reason == REASON_INODE ? "inode" : "unknown";
    printf("[POLICE] DENIED cmd=%d pid=%u comm=%.16s cgroup=%llu inode=%llu reason=%s\n",
           e->cmd, e->pid, e->comm, (unsigned long long)e->cgid,
           (unsigned long long)e->inode, reason_str);
    fflush(stdout);

    /* Forward the event as JSON to the frontend middleman. */
    monitor_send_police(mon,
                        e->pid,
                        e->comm,
                        (unsigned long long)e->cgid,
                        (unsigned long long)e->inode,
                        e->cmd,
                        reason_str);
    return 0;
}

struct police *police_open(void)
{
    struct police *p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;

    p->skel = police_bpf__open_and_load();
    if (!p->skel) {
        int saved = errno;
        free(p);
        errno = saved;
        return NULL;
    }
    return p;
}

void police_close(struct police *p)
{
    if (!p)
        return;
    /* Destroy the LSM BPF program link before destroying the skeleton.
     * bpf_link__destroy both detaches the program from the kernel hook
     * and releases the link fd, ensuring a subsequent auditor instance
     * can start with a clean policy state. */
    if (p->skel && p->skel->links.police_bpf)
        bpf_link__destroy(p->skel->links.police_bpf);
    ring_buffer__free(p->rb);
    police_bpf__destroy(p->skel);
    free(p);
}

int police_attach(struct police *p, struct monitor *mon)
{
    int err;

    p->mon = mon;

    err = police_bpf__attach(p->skel);
    if (err)
        return err;

    p->rb = ring_buffer__new(bpf_map__fd(p->skel->maps.events), on_event,
                             p->mon, NULL);
    return p->rb ? 0 : -errno;
}

int police_poll(struct police *p, int timeout_ms)
{
    if (!p || !p->rb)
        return -EINVAL;
    return ring_buffer__poll(p->rb, timeout_ms);
}

static int path_to_id(const char *path, uint64_t *id)
{
    struct stat st;

    if (stat(path, &st))
        return -errno;

    if (!S_ISDIR(st.st_mode))
        return -ENOTDIR;

    *id = st.st_ino;
    return 0;
}

static int map_update_id(struct police *p, struct bpf_map *map, uint64_t id, int op)
{
    uint8_t one = 1;

    if (op == 0) /* add */
        return bpf_map__update_elem(map, &id, sizeof(id), &one, sizeof(one), BPF_ANY);
    else /* remove */
        return bpf_map__delete_elem(map, &id, sizeof(id), 0);
}

int police_deny_id(struct police *p, uint64_t cgid)
{
    return map_update_id(p, p->skel->maps.denied_cgroups, cgid, 0);
}

int police_allow_id(struct police *p, uint64_t cgid)
{
    return map_update_id(p, p->skel->maps.denied_cgroups, cgid, 1);
}

int police_deny_path(struct police *p, const char *path)
{
    uint64_t id;
    int err = path_to_id(path, &id);
    return err ? err : police_deny_id(p, id);
}

int police_allow_path(struct police *p, const char *path)
{
    uint64_t id;
    int err = path_to_id(path, &id);
    return err ? err : police_allow_id(p, id);
}

int police_deny_inode(struct police *p, uint64_t inode)
{
    return map_update_id(p, p->skel->maps.denied_inodes, inode, 0);
}

int police_allow_inode(struct police *p, uint64_t inode)
{
    return map_update_id(p, p->skel->maps.denied_inodes, inode, 1);
}

/* PID deny list — keys are u32 PIDs. Unlike cgroup-based denial, this
 * works without writing to cgroup.procs (broken under WSL2). */
static int map_update_pid(struct police *p, struct bpf_map *map, uint32_t pid, int op)
{
    uint8_t one = 1;
    if (op == 0) /* add */
        return bpf_map__update_elem(map, &pid, sizeof(pid), &one, sizeof(one), BPF_ANY);
    else /* remove */
        return bpf_map__delete_elem(map, &pid, sizeof(pid), 0);
}

int police_deny_pid(struct police *p, uint32_t pid)
{
    return map_update_pid(p, p->skel->maps.denied_pids, pid, 0);
}

int police_allow_pid(struct police *p, uint32_t pid)
{
    return map_update_pid(p, p->skel->maps.denied_pids, pid, 1);
}

/* Walk every directory entry under cgroup_path, stat each subdirectory,
 * and deny its inode. Recurses into nested cgroups. */
static int deny_tree_recursive(struct police *p, const char *path, int depth)
{
    DIR *dir;
    struct dirent *entry;
    char child_path[PATH_MAX];
    uint64_t id;
    int err;

    if (depth > 64)
        return -ELOOP;

    dir = opendir(path);
    if (!dir)
        return -errno;

    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name);

        {
            struct stat st;
            if (stat(child_path, &st))
                continue;
            if (!S_ISDIR(st.st_mode))
                continue;
            id = st.st_ino;
        }

        err = police_deny_id(p, id);
        if (err) {
            closedir(dir);
            return err;
        }

        /* Recurse into nested cgroup directories. */
        err = deny_tree_recursive(p, child_path, depth + 1);
        if (err) {
            closedir(dir);
            return err;
        }
    }

    closedir(dir);
    return 0;
}

int police_deny_subtree(struct police *p, const char *cgroup_path)
{
    uint64_t id;
    int err = path_to_id(cgroup_path, &id);
    if (err)
        return err;

    err = police_deny_id(p, id);
    if (err)
        return err;

    return deny_tree_recursive(p, cgroup_path, 0);
}

static int allow_tree_recursive(struct police *p, const char *path, int depth)
{
    DIR *dir;
    struct dirent *entry;
    char child_path[PATH_MAX];
    uint64_t id;
    int err;

    if (depth > 64)
        return -ELOOP;

    dir = opendir(path);
    if (!dir)
        return -errno;

    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name);

        {
            struct stat st;
            if (stat(child_path, &st))
                continue;
            if (!S_ISDIR(st.st_mode))
                continue;
            id = st.st_ino;
        }

        err = police_allow_id(p, id);
        if (err) {
            closedir(dir);
            return err;
        }

        err = allow_tree_recursive(p, child_path, depth + 1);
        if (err) {
            closedir(dir);
            return err;
        }
    }

    closedir(dir);
    return 0;
}

int police_allow_subtree(struct police *p, const char *cgroup_path)
{
    uint64_t id;
    int err = path_to_id(cgroup_path, &id);
    if (err)
        return err;

    err = police_allow_id(p, id);
    if (err)
        return err;

    return allow_tree_recursive(p, cgroup_path, 0);
}

int police_set_audit_only(struct police *p, int enabled)
{
    uint32_t key = 0;
    uint32_t val = enabled ? 1 : 0;

    return bpf_map__update_elem(
        p->skel->maps.police_config,
        &key, sizeof(key),
        &val, sizeof(val),
        BPF_ANY
    );
}
