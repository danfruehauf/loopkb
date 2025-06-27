#include <stdio.h>

#include "log.h"

#define MAX_LINE_LENGTH 256

int loopkb_log_level_stdout = 0;
int loopkb_log_level_stderr = 0;

const char* log_level_strings[] =
{
	"TRACE",
	"DEBUG",
	"INFO",
	"WARN",
	"ERR"
};

int __loopkb_log(enum log_level_t log_level, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	const int retval = __loopkb_log_args(log_level, format, args);
	va_end(args);
	return retval;
}

int __loopkb_log_args(enum log_level_t log_level, const char* format, va_list args)
{
	static __thread char lineBuffer[MAX_LINE_LENGTH];
	FILE* stream = NULL;

	if (log_level >= loopkb_log_level_stdout)
	{
		stream = stdout;
	}

	if (log_level >= loopkb_log_level_stderr)
	{
		stream = stderr;
	}

	if (stream == NULL)
	{
		return 0;
	}

	int byteCount = snprintf(lineBuffer, MAX_LINE_LENGTH, "%s: ", log_level_strings[log_level]);
	vsnprintf(lineBuffer + byteCount, MAX_LINE_LENGTH - byteCount, format, args);
	int retval = fprintf(stream, "%s\n", lineBuffer);
	fflush(stream);
	return retval;
}
