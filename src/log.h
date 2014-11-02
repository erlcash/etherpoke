#ifndef _LOG_H
#define _LOG_H

#include <syslog.h>

#define log_info(format, args...) syslog (LOG_INFO, format"\n", ##args)
#define log_warning(format, args...) syslog (LOG_WARNING, format"\n", ##args)
#define log_error(format, args...) syslog (LOG_ERR, format"\n", ##args)
#define log_debug(format, args...) syslog (LOG_DEBUG, format"\n", ##args)

#endif

