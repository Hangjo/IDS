#include "packetsniff.h"
#include <ctype.h>

#define HOST "localhost"
#define USER "root"
#define PASSWORD "raspberry"

#define PORTSFILE "ports.txt"
#define SPACE " "
#define COMMENTMARKER '#'
#define CHARSTOREMOVE "[] "
#define NEWLINEMARKER '\n'
#define PORTSEPARATOR ","
#define MUSTHAVE '!'

#define BUFFER 4096
#define QUERYSIZE 2048

//Checks if string is empty
int isEmpty (const char string[]) {
	while (*string != '\0') {
		if (!isspace((unsigned char) * string)) {
			return 0;
		}

		string++;
	}

	return 1;
}

//Removes characters that are in the CHARSTOREMOVE variable
void removechars (char string[]) {
	char fixed[QUERYSIZE] = "\0";
	char stringcopy[QUERYSIZE] = "\0";
	strcpy(stringcopy, string);

	char * save = stringcopy;
	char * nonbracket = strtok_r(stringcopy, CHARSTOREMOVE, &save);

	while (nonbracket != NULL) {
		strcat(fixed, nonbracket);
		nonbracket = strtok_r(save, CHARSTOREMOVE, &save);
	}

	strcpy(string, fixed);
}

//Takes ports from ports.txt and inserts them into the mysql database
int getPorts(char DATABASE[], MYSQL * conn) {
	FILE * ports;

	if (conn == NULL) {
		mysqlerror(conn);
	}

	ports = fopen(PORTSFILE, "r");

	if (ports == NULL) {
		printf("Failed to open ports file.");
		return -1;
	}

	char portline[BUFFER];

	//Empties port table before inserting
	char query[QUERYSIZE] = "TRUNCATE TABLE ports;";

	if (mysql_query(conn, query)) {
		mysqlerror(conn);
	}

	while (fgets(portline, BUFFER, ports)) {
		if (portline[0] != COMMENTMARKER && portline[0] != NEWLINEMARKER && !isEmpty(portline)) {
			char * temp;
			char * listname = strtok_r(portline, SPACE, &temp);
			
			removechars(temp);
					
			char * port = strtok_r(temp, PORTSEPARATOR, &temp);
			
			while (port != NULL) {
				int required = 0;

				if (port[0] == MUSTHAVE) {
					required = 1;
					port++;
				}

				memset(query, '\0', sizeof(query));
				snprintf(query + strlen(query), QUERYSIZE, "INSERT INTO ports (varname, port, required) VALUES ('$%s', '%s', '%d');", listname, port, required);
				if (mysql_query(conn, query)) {
					mysqlerror(conn);
				}

				port = strtok_r(temp, PORTSEPARATOR, &temp);
			}
		}
	}

	fclose(ports);

	return 1;
}
