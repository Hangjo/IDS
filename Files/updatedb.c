#include "updatedb.h"
#include "readrules.h"

#define DATABASE "IDS"			//Database to use for mysql
#define PASSWORD "raspberry"		//Password for mysql
#define USER "root"			//User for mysql
#define HOST "localhost"		//Host for mysql
#define RULEFILE "community.rules"	//Name of file that contains rules

#define COMMENT '#'			//Symbol used to comment out lines in the community.rules file

#define QUERYSIZE 4096			//Maximum size allowed for mysql queries
#define BUFFER 4096			//Buffer size
#define BASE 10				//Base to use for conversion of strings to long

//Prints error for mysql
void mysqlerror (MYSQL * updateconn) {
	fprintf(stderr, "%s\n", mysql_error(updateconn));
}

//Closes mysql connection and marks end of library to prevent any memory leaks
void closemysql (MYSQL * updateconn) {
	mysql_close(updateconn);
	mysql_library_end();
}

//Removes previous revisions of rules so only the newest is kept in the database
int removeoldrules (MYSQL * updateconn) {
	//Gets all rows in the table that are older versions of rules
	char query[QUERYSIZE] = "SELECT DISTINCT r1.sid, r1.rev FROM rules r1, rules r2 WHERE r1.sid = r2.sid AND r1.rev < r2.rev;";

	//If query fails
	if (mysql_query(updateconn, query)) {
		mysqlerror(updateconn);
		return -1;
	}

	//Storing result from query
	MYSQL_RES * oldrules = mysql_store_result(updateconn);
	MYSQL_ROW row;

	//If results weren't stored correctly
	if (oldrules == NULL) {
		mysqlerror(updateconn);
		return -1;
	}
		
	//Removes rules from query from the content and rules tables
	while (row = mysql_fetch_row(oldrules)) {
		memset(query, '\0', sizeof(query));
		snprintf(query + strlen(query), QUERYSIZE, "DELETE r, c FROM content c JOIN rules r ON r.sid = c.sid AND r.rev = c.rev WHERE r.sid = %s AND r.rev = %s;", row[0], row[1]);	

		if (mysql_query(updateconn, query)) {
			mysqlerror(updateconn);
		}
	}

	mysql_free_result(oldrules);
	return 1;
}

//Removes any rules that have been commented out from the rule file if they are in the database
int removecommentrules (MYSQL * updateconn) {
	FILE * rules;		//File for rules
	char line[BUFFER];	//String to hold individual lines from the file

	rules = fopen(RULEFILE, "r");

	//If file doesn't open
	if (rules == NULL) {
		printf("Failed to open file.\n");
		return -1;
	}

	//Searches through rules file line by line
	while(fgets(line, BUFFER, rules) != NULL) {
		//Looks for lines that have been commented out to determine if a rule has been removed
		if (line[0] == COMMENT) {
			char temp[BUFFER];
			char query[BUFFER] = "\0";
			//If the line is a rule, take the sid and see if it exists in the table
			if (strstr(line, " sid:") != NULL) {
				strcpy(temp, strstr(line, " sid:"));
				char * sid;
				char * sidfield = strtok(temp, ";");
				char * label = strtok_r(sidfield, ":", &sid);

				snprintf(query + strlen(query), BUFFER, "SELECT * FROM rules WHERE sid = %s;", sid);

				if (mysql_query(updateconn, query)) {
					mysqlerror(updateconn);
				}

				//Results from the query, if it is not empty, there are rules that need to be removed
				MYSQL_RES * rule = mysql_store_result(updateconn);
				MYSQL_ROW row;
	
				if (rule == NULL) {
					mysqlerror(updateconn);
					return -1;
				}

				//Removes rules from table if they were commented out
				while (row = mysql_fetch_row(rule)) {
					memset(query, '\0', sizeof(query));
					snprintf(query + strlen(query), BUFFER, "DELETE r, c FROM content c JOIN rules r ON r.sid = c.sid  WHERE r.sid = %s;" , sid);

					if (mysql_query(updateconn, query)) {
						mysqlerror(updateconn);
					}
				}

				mysql_free_result(rule);
			}
		}
	}

	fclose(rules);
}

//Removes rules that have been deleted from the rules file
//Takes a while, needs a faster method
int removedeletedrules (MYSQL * updateconn) {
	FILE * rules;	//File for rules

	rules = fopen(RULEFILE, "r");

	//If rules file doesn't open
	if (rules == NULL) {
		printf("Failed to open file.\n");
		return -1;
	}

	//Get all sids in the database
	char query[BUFFER] = "SELECT DISTINCT sid FROM rules;";

	if (mysql_query(updateconn, query)) {
		mysqlerror(updateconn);
		return -1;
	}

	MYSQL_RES * allsid = mysql_store_result(updateconn);
	MYSQL_ROW row;

	if (allsid == NULL) {
		mysqlerror(updateconn);
		return -1;
	}

	//Search the file for all the sids, if one isn't found, that means the rule was deleted from the file and needs to be removed from the database
	while (row = mysql_fetch_row(allsid)) {
		char line[BUFFER];
		int found = 0;

		char sid[BUFFER] = "\0";
		snprintf(sid + strlen(sid), BUFFER, "sid:%s;", row[0]);

		//Gets individual lines from the file
		while (fgets(line, BUFFER, rules) != NULL) {
			if (strstr(line, sid) != NULL) {
				found = 1;
			}
		}

		//Deletes the rule if it was not found in the file
		if (!found) {
			memset(query, '\0', sizeof(query));		
			snprintf(query + strlen(query), BUFFER, "DELETE r, c FROM content c JOIN rules r ON r.sid = c.sid  WHERE r.sid = %s;" , row[0]);

			if (mysql_query(updateconn, query)) {
				mysqlerror(updateconn);
			}
		}

		//Point back to the beginning of the file
		rewind(rules);
	}

	fclose(rules);
	mysql_free_result(allsid);
}

int main () {
	MYSQL * updateconn = mysql_init(NULL);	//Connection to mysql

	if (updateconn == NULL) {
		mysqlerror(updateconn);
		return -1;
	}

	//Connects to the mysql database
	if (mysql_real_connect(updateconn, HOST, USER, PASSWORD, DATABASE, 0, NULL, 0)) {
		getRules(DATABASE, updateconn);
		removeoldrules(updateconn);
		removecommentrules(updateconn);
		removedeletedrules(updateconn);
	} else {
		mysqlerror(updateconn);
	}
	
	closemysql(updateconn);
	return 1;
}
