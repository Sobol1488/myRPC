#ifndef LIBMYSYSLOG_H
#define LIBMYSYSLOG_H

#include <syslog.h>

void log_error(const char *message);
void log_info(const char *message);

#endif
