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
