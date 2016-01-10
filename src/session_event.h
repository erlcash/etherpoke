/*
 * Copyright (c) 2013 - 2016, CodeWard.org
 */
#ifndef _SESSION_EVENT_H
#define _SESSION_EVENT_H

enum
{
	SE_NUL = 0x00,
	SE_BEG = 0x01,
	SE_END = 0x02,
	SE_ERR = 0x03
};

struct session_event
{
	int type;
	time_t ts;
};

#endif

