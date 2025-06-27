#pragma once

#include <stdarg.h>
#include <stdint.h>

extern int loopkb_log_level_stdout;
extern int loopkb_log_level_stderr;
extern const char* log_level_strings[];

enum log_level_t : uint8_t
{
	log_level_trace,
	log_level_debug,
	log_level_info,
	log_level_warning,
	log_level_error
};

int __loopkb_log(enum log_level_t log_level, const char* format, ...);
int __loopkb_log_args(enum log_level_t log_level, const char* format, va_list args);
