#ifndef readrules
#define readrules

#include <stdio.h>
#include <stdlib.h>
#include <mysql/mysql.h>
#include <string.h>
#include <ctype.h>

#define STATEMENTSIZE 4096

struct queryvals {
	char columns[STATEMENTSIZE];
	char values[STATEMENTSIZE];
};

int getRules(char DATABASE[], MYSQL * conn);

#endif
