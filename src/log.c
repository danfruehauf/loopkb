/*
    Copyright (C) 2025 Dan Fruehauf <malkodan@gmail.com>.
    All rights reserved.

    This file is part of loopkb.

    loopkb is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    loopkb is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with loopkb.  If not, see <http://www.gnu.org/licenses/>.
*/

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
