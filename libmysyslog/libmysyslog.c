#include "libmysyslog.h"
#include <stdio.h>
#include <stdlib.h>

void log_error(const char *message) {
    openlog("myRPC", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_ERR, "ERROR: %s", message);
    closelog();
}

void log_info(const char *message) {
    openlog("myRPC", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "INFO: %s", message);
    closelog();
}
