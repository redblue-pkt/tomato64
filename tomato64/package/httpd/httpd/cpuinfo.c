/*
 *
 * Tomato Firmware
 *
 * Fixes/updates (C) 2018 - 2025 pedro
 * https://freshtomato.org/
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef TOMATO64
#include <sys/sysinfo.h>
#endif /* TOMATO64 */
#include "tomato.h"


#if 0
static float g_cpu_used;
static unsigned int cpu_num;
#endif /* 0 */

struct occupy
{
	char name[20];
	unsigned int user;
	unsigned int nice;
	unsigned int system;
	unsigned int idle;
#ifdef TCONFIG_BCMARM
	unsigned int io;
	unsigned int irq;
	unsigned int sirq;
#endif
};

#if 0
static void cal_occupy(struct occupy *, struct occupy *);
static void get_occupy(struct occupy *);
#endif /* 0 */

static void trim(char *str)
{
	char *copied, *tail = NULL;
	if (str == NULL)
		return ;

	for (copied = str; *str; str++) {
		if ((unsigned char)*str > 0x20) {
			*copied++ = *str;
			tail = copied;
		}
		else {
			if (tail)
				*copied++ = *str;
		}
	}

	if (tail)
		*tail = 0;
	else
		*copied = 0;
	return;
}

#ifdef TOMATO64
static unsigned int get_cpufreq(void)
{
	FILE *fd;
	char buf[64];
	unsigned long long khz;
	char *end;
	const char *paths[] = {
		"/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_cur_freq",
		"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq",
		NULL
	};
	const char **p;

	for (p = paths; *p; ++p) {
		if (access(*p, R_OK) != 0)
			continue;

		memset(buf, 0, sizeof(buf));
		if ((fd = fopen(*p, "r")) == NULL)
			continue;

		if (fgets(buf, sizeof(buf), fd) == NULL) {
			fclose(fd);
			continue;
		}
		fclose(fd);

		khz = strtoull(buf, &end, 10);
		if (end == buf)
			continue;

		if (khz < 1000ULL)
			return 0;

		if ((khz / 1000ULL) > 20000ULL)
			return 0;

		return (unsigned int)(khz / 1000ULL);
	}

	return 0;
}

static char *get_cpuclk(char *cpuclk, size_t cpuclk_sz, unsigned int mhz)
{
	if (!cpuclk || cpuclk_sz == 0)
		return NULL;

	if (mhz == 0)
		return NULL;

	snprintf(cpuclk, cpuclk_sz, "%u", mhz);
	return cpuclk;
}

static char *get_cpugovernor(void)
{
	static char govbuf[64];
	FILE *fd;
	const char *paths[] = {
		"/sys/devices/system/cpu/cpufreq/policy0/scaling_governor",
		"/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
		NULL
	};
	const char **p;

	for (p = paths; *p; ++p) {
		if (access(*p, R_OK) != 0)
			continue;

		if ((fd = fopen(*p, "r")) == NULL)
			continue;

		if (fgets(govbuf, sizeof(govbuf), fd) == NULL) {
			fclose(fd);
			continue;
                }
		fclose(fd);

		govbuf[strcspn(govbuf, "\r\n")] = '\0';

		if (govbuf[0] != '\0')
			return govbuf;
	}

	return NULL;
}
#endif

/*
 * - ARM:
 * Processor               : ARMv7 Processor rev 0 (v7l
 * - MIPS:
 * system type             : Broadcom BCM5354 chip rev 2 pkg 0
 *
 * processor               : 0
 * cpu model               : BCM3302 V2.9
 * BogoMIPS                : 238.38
 */
static int strncmp_ex(char *str1, char *str2)
{
	return strncmp(str1, str2, strlen(str2));
}

#ifdef TCONFIG_BCMARM
void get_cpuinfo(char *system_type, const size_t buf_system_type_sz, char *cpuclk, const size_t buf_cpuclk_sz, char *cputemp, const size_t buf_cputemp_sz,
                 char* cpugovernor, const size_t buf_cpugovernor_sz)
#else
void get_cpuinfo(char *system_type, const size_t buf_system_type_sz, char *cpuclk, const size_t buf_cpuclk_sz)
#endif
{
	FILE *fd;
	char *next;
	char buff[1024];
	char title[128], value[512];

	memset(buff, 0, sizeof(buff));
	if ((fd = fopen("/proc/cpuinfo", "r"))) {
		while (fgets(buff, sizeof(buff), fd)) {
			next = buff;
			memset(title, 0, sizeof(title));
			strlcpy(title, strsep(&next, ":"), sizeof(title));
			if (next == NULL)
				continue;

			memset(value, 0, sizeof(value));
			strlcpy(value, next, sizeof(value));
			trim(value);
#ifndef TOMATO64
#ifdef TCONFIG_BCMARM
			if (strncmp_ex(title, "Processor") == 0) {
#else
			if (strncmp_ex(title, "system type") == 0) {
#endif
#endif /* TOMATO64 */
#ifdef TOMATO64
			if (strncmp_ex(title, "vendor_id") == 0) {
#endif /* TOMATO64 */
#ifndef TCONFIG_BCMARM
				if (strncmp_ex(value, "Broadcom BCM5354") == 0)
					strlcpy(system_type, "Broadcom BCM5354", buf_system_type_sz);
				else
#endif
					strlcpy(system_type, value, buf_system_type_sz);
			}
#ifndef TCONFIG_BCMARM
			if (strncmp_ex(title, "cpu MHz") == 0)
				strlcpy(cpuclk, value, buf_cpuclk_sz);
#endif
#ifdef TOMATO64
			if (strncmp_ex(title, "cpu MHz") == 0)
				strlcpy(cpuclk, value, buf_cpuclk_sz);
#endif /* TOMATO64 */
		}
		fclose(fd);
	}

#ifdef TCONFIG_BCMARM
	memset(buff, 0, sizeof(buff));
	system("/usr/sbin/sysinfo-helper");
	if ((fd = fopen("/tmp/sysinfo-helper", "r"))) {
		while (fgets(buff, sizeof(buff), fd)) {
			next = buff;
			memset(title, 0, sizeof(title));
			strlcpy(title, strsep(&next, ":"), sizeof(title));
			if (next == NULL)
				continue;

			memset(value, 0, sizeof(value));
			strlcpy(value, next, sizeof(value));
			trim(value);
#ifndef TOMATO64
			if (strncmp_ex(title, "cpu MHz") == 0)
					strlcpy(cpuclk, value, buf_cpuclk_sz);
#endif /* TOMATO64 */

			if (strncmp_ex(title, "cpu Temp") == 0)
				strlcpy(cputemp, value, buf_cputemp_sz);
		}
		fclose(fd);
	}
#endif
#ifdef TOMATO64_ARM64
	int cpu_freq = get_cpufreq();
	char *cpu_gov = get_cpugovernor();
	if (!cpu_gov) {
		strlcpy(cpugovernor, "NONE", buf_cpugovernor_sz);
	} else {
		strlcpy(cpugovernor, cpu_gov, buf_cpugovernor_sz);
	}
#if TOMATO64_RPI4
	strlcpy(system_type, "Broadcom BCM2711", buf_system_type_sz);
	if (cpu_freq > 0) {
		strlcpy(cpuclk, get_cpuclk(cpuclk, buf_cpuclk_sz, cpu_freq), buf_cpuclk_sz);
	} else {
		strlcpy(cpuclk, "1800", buf_cpuclk_sz);
	}
#elif TOMATO64_R6S
	strlcpy(system_type, "Rockchip RK3588S", buf_system_type_sz);
	if (cpu_freq > 0) {
		strlcpy(cpuclk, get_cpuclk(cpuclk, buf_cpuclk_sz, cpu_freq), buf_cpuclk_sz);
	} else {
		strlcpy(cpuclk, "2400", buf_cpuclk_sz);
	}
#elif TOMATO64_NEO3
	strlcpy(system_type, "Rockchip RK3328", buf_system_type_sz);
	if (cpu_freq > 0) {
		strlcpy(cpuclk, get_cpuclk(cpuclk, buf_cpuclk_sz, cpu_freq), buf_cpuclk_sz);
	} else {
		strlcpy(cpuclk, "1300", buf_cpuclk_sz);
	}
#else
	strlcpy(system_type, "MediaTek Filogic 830", buf_system_type_sz);
	if (cpu_freq > 0) {
		strlcpy(cpuclk, get_cpuclk(cpuclk, buf_cpuclk_sz, cpu_freq), buf_cpuclk_sz);
	} else {
		strlcpy(cpuclk, "2000", buf_cpuclk_sz);
	}
#endif
	FILE *f;
	char buffer[8];
	int temp;

#if TOMATO64_R6S
	const char cmd[] = "sensors -A package_thermal-virtual-0 | grep 'temp1' | awk '{print $2}' | sed 's/+//; s/°C//'";
#elif TOMATO64_NEO3
	const char cmd[] = "sensors -A soc_thermal-virtual-0 | grep 'temp1' | awk '{print $2}' | sed 's/+//; s/°C//'";
#else
	const char cmd[] = "sensors -A cpu_thermal-virtual-0 | grep 'temp1' | awk '{print $2}' | sed 's/+//; s/°C//'";
#endif

	if ((f = popen(cmd, "r"))) {
		if (fgets(buffer, sizeof(buffer), f) != NULL) {
			buffer[strcspn(buffer, "\n")] = 0;
			temp = (int)(atof(buffer) + 0.5);
			snprintf(cputemp, buf_cputemp_sz, "%d", temp);
		}
		pclose(f);
	}
	else {
		snprintf(cputemp, buf_cputemp_sz, "");
	}
#endif /* TOMATO64_ARM64 */
}

#ifdef TOMATO64
void get_cpumodel(char *cpumodel, const size_t buf_cpumodel_sz)
{
#ifdef TOMATO64_X86_64
	FILE *fd;
	char *next;
	char buff[1024];
	char title[128], value[512];

	memset(buff, 0, sizeof(buff));
	if ((fd = fopen("/proc/cpuinfo", "r"))) {
		while (fgets(buff, sizeof(buff), fd)) {
			next = buff;
			memset(title, 0, sizeof(title));
			strlcpy(title, strsep(&next, ":"), sizeof(title));
			if (next == NULL)
				continue;

			memset(value, 0, sizeof(value));
			strlcpy(value, next, sizeof(value));
			trim(value);

			if (strncmp_ex(title, "model name") == 0) {
				strlcpy(cpumodel, value, buf_cpumodel_sz);
			}
		}
		fclose(fd);
	}
#endif /* TOMATO64_X86_64 */
#ifdef TOMATO64_ARM64
#if TOMATO64_RPI4
	strlcpy(cpumodel, "ARM Cortex-A72", buf_cpumodel_sz);
#elif TOMATO64_R6S
	strlcpy(cpumodel, "ARM Cortex-A76 / A55", buf_cpumodel_sz);
#elif TOMATO64_NEO3
	strlcpy(cpumodel, "ARM Cortex-A53", buf_cpumodel_sz);
#else
	strlcpy(cpumodel, "MediaTek MT7986AV (Cortex-A53)", buf_cpumodel_sz);
#endif
#endif /* TOMATO64_ARM64 */
}
#endif /* TOMATO64 */

#if 0
float get_cpupercent(void)
{
	struct occupy ocpu[10];
	struct occupy ncpu[10];
	unsigned int i;

	//cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
	cpu_num = 1;
	get_occupy(ocpu);
	sleep(1);
	get_occupy(ncpu);
	for (i = 0; i < cpu_num; i++) {
		cal_occupy(&ocpu[i], &ncpu[i]);
	}

	return g_cpu_used;
}

static void cal_occupy (struct occupy *o, struct occupy *n)
{
	double od, nd;
	double id, sd;

#ifdef TCONFIG_BCMARM
	od = (double) (o->user + o->nice + o->system + o->idle + o->io + o->irq + o->sirq);
	nd = (double) (n->user + n->nice + n->system + n->idle + n->io + n->irq + n->sirq);
#else
	od = (double) (o->user + o->nice + o->system + o->idle);
	nd = (double) (n->user + n->nice + n->system + n->idle);
#endif

	id = (double) (n->user - o->user);
	sd = (double) (n->system - o->system);
	g_cpu_used = ((sd + id) * 100.0) / (nd - od);
}

static void get_occupy (struct occupy *o)
{
	FILE *fd;
	unsigned int n;
	char buff[1024];

	if ((fd = fopen("/proc/stat", "r"))) {
		fgets(buff, sizeof(buff), fd);

		for (n = 0; n < cpu_num; n++) {
			fgets(buff, sizeof(buff), fd);
#ifdef TCONFIG_BCMARM
			sscanf(buff, "%s %u %u %u %u %u %u %u", o[n].name, &o[n].user, &o[n].nice, &o[n].system, &o[n].idle, &o[n].io, &o[n].irq, &o[n].sirq);
#else
			sscanf(buff, "%s %u %u %u %u", o[n].name, &o[n].user, &o[n].nice, &o[n].system, &o[n].idle);
#endif
		}
		fclose(fd);
	}
}
#endif /* 0 */
