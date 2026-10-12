#pragma once
#include <stdint.h>

struct auditor;

struct auditor *auditor_open(void);
void auditor_close(struct auditor* a);
int auditor_attach(struct auditor *a);
int auditor_poll(struct auditor *a, int timeout_ms);