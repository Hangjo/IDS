#ifndef scanpacket
#define scanpacket

#include "packetsniff.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <mysql/mysql.h>

int scan(const char * payload, const char * hexpayload, const char * lowerhex, const struct sniff_ip * ip, const struct sniff_tcp * tcp, MYSQL * conn);

#endif
