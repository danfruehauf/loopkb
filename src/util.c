#include <time.h>

#include "util.h"

__int64_t system_clock_ns()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	__int64_t ns = ts.tv_sec * 1e9 + ts.tv_nsec;
	return ns;
}

__int64_t system_clock_us()
{
	return system_clock_ns() / 1000;
}
