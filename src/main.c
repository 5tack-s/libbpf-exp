#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include "police.h"
#include "auditor.h"

static volatile sig_atomic_t exit = 0;

static void sig_handler(int sig){
	exit = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if(level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
 
}

int main(int argc, char **argv)
{
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct police *p = NULL;
	struct auditor *a = NULL;
	int err;
	int rc = 1;

	if(argc != 2){
		fprintf(stderr, "usage: %s /sys/fs/cgroup/<cgroup>", argv[0]);
		return rc;
	}

	p = police_open();
	a = auditor_open();

	if(!p){
		fprintf(stderr, "[FATAL] Failed to load police: %s\n", strerror(errno));
		goto out;
	}

	if(!a){
		fprintf(stderr, "[FATAL] Failed to load the auditor: %s\n", strerror(errno));
		goto out;
	}

	err = police_attach(p);
	if(err){
		fprintf(stderr, "[FATAL] Failed to attach to police: %s\n", strerror(-err));
		goto out;
	}
	err = auditor_attach(a);
	if(err){
		fprintf(stderr, "[FATAL] Failed to attach to the auditor: %s\n", strerror(-err));
		goto out;
	}

	//experimental tricks
	err = police_deny_path(p, argv[1]);
	if(err){
		fprintf(stderr, "deny: %s %s\n", argv[1], strerror(-err));
		goto out;
	}

	while(!exit){
		err = police_poll(p,100);
		if(err == -EINTR)
			break;
		if(err < 0){
			fprintf(stderr, "police poll: %s\n", strerror(-err));
			goto out;
		}

		
		err = auditor_poll(a,0);
		if(err < 0 && err != EINTR){
			fprintf(stderr, "auditor poll: %s\n", strerror(-err));
			goto out;
		}
	}

	rc = 0;

	out:
		police_close(p);
		auditor_close(a);
		return rc;



}

