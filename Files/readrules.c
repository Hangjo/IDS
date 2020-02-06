#include "readrules.h"
#include "packetsniff.h"

#define USER "root"			//Username for mysql database
#define PASSWORD "raspberry"		//Password for mysql database
#define RULETABLE "rules"		//Table containing the rules
#define CONTENTTABLE "content"		//Table containing the content for rules
#define HOST "localhost"		//Host of database
#define RULEFILE "community.rules"	//Name of file containing rules 

#define CONTENTQUERY "content, hexcontent, lowerhexcontent, nocase, httpclientbody, httpcookie, httprawcookie, httpheader, httprawheader, httpmethod, httpuri, httprawuri, httpstatcode, httpstatmsg,fastpattern, distance, within, depth, offset, contentcount, sid, rev"

#define LINESIZE 4096			//Largest size of rule line pulled from rule file
#define NUMRULEHEADERS 6		//Number of rule headers in the rule file
#define CONTENTFIELD 64			//Buffer size for content field array
#define NUMCONTENTFIELDS 17		//Numbers of content field modifiers
#define SYMBOLSTOREMOVE "();"		//Symbols to be removed from rule names
#define HEADERSEPARATOR " "		//Character that separates the headers in the rule file
#define OPTIONSSEPARATOR ";"		//Character that separates each rule option in the rule file
#define ARGUMENTSEPARATOR ":"		//Character that separates rule names from their arguments

char * nocase (char * string) {
	static char lower[LINESIZE];
	memset(lower, '\0', sizeof(lower));
	int count = 0;

	while (string[count]) {
		snprintf(lower + strlen(lower), LINESIZE, "%c", tolower(string[count]));	
		count++;
	}

	return lower;
}

//Checks if given string is only spaces
int isempty(const char * string) {
	while (*string != '\0') {
		if (!isspace((unsigned char) *string)) {
			return 0;		
		}

		string++;
	}
	return 1;
}

//Adds value to query to be entered into rules database
char * addtoquery (char statement[], char value[]) {
	if (isempty(statement)) {
		snprintf(statement + strlen(statement), STATEMENTSIZE, "'%s'", value);
	} else {
		snprintf(statement + strlen(statement), STATEMENTSIZE, ", '%s'", value);
	}

	return statement;
}

//Converts ascii strings to hex
char * contenttohex (const char helper[]) {
	static char hex[LINESIZE];
	memset(hex, '\0', sizeof(hex));

	for (int i = 1; i < strlen(helper) - 1; i++) {
		if (helper[i] != '|') {
			snprintf(hex + strlen(hex), LINESIZE, "%02x", helper[i]);
		} else {
			i++;

			while (helper[i] != '|') {
				snprintf(hex + strlen(hex), LINESIZE, "%c", helper[i]);
				i++;
			}	
		}

		if (i < strlen(helper) - 2) {
			strcat(hex, " ");
		}
	}

	return hex;
}

//Removes any symbols from string to be entered into database
char * removesymbols (char string[]) {
	static char fixedstring[STATEMENTSIZE];
	memset(fixedstring, '\0', sizeof(fixedstring));

	char * stringsave = string;

	char * nonsymbols = strtok_r(string, SYMBOLSTOREMOVE, &stringsave);

	if (nonsymbols == NULL) {
		return string;
	}

	while (nonsymbols != NULL){
		strcat(fixedstring, nonsymbols);
		nonsymbols = strtok_r(stringsave, SYMBOLSTOREMOVE, &stringsave);		
	}

	return fixedstring;
}

//Adds second apostrophe so mysql will accept 
char * addapos (char string []) {
	char temp[STATEMENTSIZE];
	memset(temp, '\0', sizeof(temp));
	char * helper = string;
	
	while((helper = strstr(helper, "'"))) {
		strncpy(temp, string, helper - string);
		temp[helper - string] = '\0';
		snprintf(temp + strlen(temp), STATEMENTSIZE, "''%s", helper + 1);
		strcpy(string, temp);
		helper += 2;
	}	

	return string;
}

//Combines the arguments of rules that are duplicates
void duplicaterules (char linecopy[], char teststring[], char * optionsave) {
	char * helper = linecopy;

	while (helper = strstr(helper, teststring)) {
		char * secondvalsave = helper;
	
		char * duprule = strtok(helper, OPTIONSSEPARATOR);
		char * secondval = strtok_r(duprule, ARGUMENTSEPARATOR, &secondvalsave);
				
		snprintf(optionsave + strlen(optionsave), STATEMENTSIZE, ", %s", secondvalsave);

		helper += (strlen(secondval) + strlen(secondvalsave) + 2);
	}	
}

//Checks if there are multiple instances of a rule option
void getduplicates(char ruleoption[], const char line[], char optionsave[]) {
	char teststring[LINESIZE];
	memset(teststring, '\0', sizeof(teststring));
	snprintf(teststring + strlen(teststring), LINESIZE, "%s:", ruleoption);

	if (strstr(line, teststring) != NULL) {
		char linecopy[LINESIZE];
		strcpy(linecopy, line);
		duplicaterules(linecopy, teststring, optionsave);
	}

}

//Separates rule option and its argument and adds to to query
struct queryvals getruleoption (struct queryvals query, char ruleoptionstring[], const char line[]) {
	//List of content modifier held in content table
	char * contentlist[] = {"content", "nocase", "http_client_body", "http_cookie", "http_raw_cookie", "http_header", "http_raw_header", "http_method", "http_uri", "http_raw_uri", "http_stat_code", "http_stat_msg", "fast_pattern", "distance", "within", "depth", "offset"};

	char rulestringcopy[LINESIZE] = "\0";
	strcpy(rulestringcopy, ruleoptionstring);
	char * optionsave = rulestringcopy;	

	//Seperates option from its argument
	char * ruleoption = removesymbols(strtok_r(rulestringcopy, ARGUMENTSEPARATOR, &optionsave));

	//Skip over empty strings and content field and its modifiers since they are entered into a seperate table 
	if (isempty(ruleoption)) {
		return query;
	}

	//Gets rid of extra spaces at beginning of string
	while (ruleoption[0] == ' ') {
		ruleoption++;
	}
	
	for (int i = 0; i < NUMCONTENTFIELDS; i++) {
		if (strcmp(contentlist[i], ruleoption) == 0) {
			return query;
		}
	}

	//If there are no arguments with rule, insert 1 into query to indicate the rule is active
	if (ruleoption == NULL) {	
		strcpy(ruleoptionstring, removesymbols(ruleoptionstring));
		if (!isempty(ruleoptionstring)) {	
			snprintf(query.columns + strlen(query.columns), STATEMENTSIZE, ", %s", ruleoptionstring);
			strcpy(query.values, addtoquery(query.values, "1"));			
		}
		
		return query;
	}
	
	//MYSQL does not allow the use of the word replace as a variable, so it must be changed
	if (strstr(ruleoption, "replace") != NULL) {
		strcpy(ruleoption, "rep");
	}
	
	//Skips copies of already inserted columns to eliminate duplicates
	if (strstr(query.columns, ruleoption) != NULL) {	
		return query;
	}
	
	getduplicates(ruleoption, line, optionsave);
	
	snprintf(query.columns + strlen(query.columns), STATEMENTSIZE, ", %s", ruleoption);

	addtoquery(query.values, addapos(optionsave));
	return query;
}

//Takes values and columns extracted from rule file and creates valid sql query to insert into table
char * createquerystatement (struct queryvals query, char table[]) {
	static char statement[STATEMENTSIZE]; 
	memset(statement, '\0', sizeof(statement));

	snprintf(statement + strlen(statement), STATEMENTSIZE, "INSERT INTO %s (%s) VALUES (%s);", table, query.columns, query.values);

	return statement;
}

//Gets modifiers of the content field that could have arguments
char * stringcontentmodifiers (const char line[], const char modifier[]) {
	if (strstr(line, modifier) != NULL && (strstr(line, modifier) < strstr(line, "content:\"") || strstr(line, "content:\"") == NULL)) {
		char copy[LINESIZE];
		memset(copy, '\0', sizeof(copy));
		strcpy(copy, line);
			
		char * fpattern = strtok(copy, OPTIONSSEPARATOR);
		char * args = NULL;
		char * temp = strtok_r(fpattern, ARGUMENTSEPARATOR, &args);
	
		if (temp != NULL) {
			return removesymbols(args);
		} else {
			return "1";
		}
	}

	return "-1";
}	

//Gets modifiers of the content field that will have a value of 1 or 0 and has no arguments
char * boolcontentmodifiers (const char line[], const char modifier[]) {
	if (strstr(line, modifier) != NULL && (strstr(line, modifier) < strstr(line, "content:\"") || strstr(line, "content:\"") == NULL)) {
		return "1";
	} 

	return "0";
}

void addmodifiers (char * query, char * save) {
	addtoquery(query, boolcontentmodifiers(save, "nocase;"));
  	addtoquery(query, boolcontentmodifiers(save, "http_client_body"));
	addtoquery(query, boolcontentmodifiers(save, "http_cookie"));
	addtoquery(query, boolcontentmodifiers(save, "http_raw_cookie"));
	addtoquery(query, boolcontentmodifiers(save, "http_header"));
	addtoquery(query, boolcontentmodifiers(save, "http_raw_header"));
	addtoquery(query, boolcontentmodifiers(save, "http_method"));
	addtoquery(query, boolcontentmodifiers(save, "http_uri"));
	addtoquery(query, boolcontentmodifiers(save, "http_raw_uri"));
	addtoquery(query, boolcontentmodifiers(save, "http_stat_code"));
	addtoquery(query, boolcontentmodifiers(save, "http_stat_msg"));
	addtoquery(query, stringcontentmodifiers(save, "fast_pattern"));
	addtoquery(query, stringcontentmodifiers(save, "distance"));
	addtoquery(query, stringcontentmodifiers(save, "within"));
	addtoquery(query, stringcontentmodifiers(save, "depth"));
	addtoquery(query, stringcontentmodifiers(save, "offset"));
}

//Gets content fields from rule and enters it into content table with sid, count of content for that rule, and if nocase applies
void getcontent (MYSQL * conn, const char rule[]) {
	char rulecopy[LINESIZE];
	memset(rulecopy, '\0', sizeof(rulecopy));
	strcpy(rulecopy, rule);

	int counter = 0;
	char * helper = rulecopy;

	char * revsave;
	char * sidsave;
	char sid[LINESIZE], rev[LINESIZE];
	strcpy(sid, strstr(rulecopy, "sid:"));
	strcpy(rev, strstr(rulecopy, "rev:"));
	char * sidhelper = strtok(sid, OPTIONSSEPARATOR);
	char * revhelper = strtok(rev, OPTIONSSEPARATOR);
	char * val = strtok_r(sidhelper, ARGUMENTSEPARATOR, &sidsave);
	val = strtok_r(revhelper, ARGUMENTSEPARATOR, &revsave);
	
	while (helper = strstr(helper, "content:\"")) {
		char * save = helper;
		char * contentfield = strtok_r(helper, OPTIONSSEPARATOR, &save);
		char * content = contentfield;
		char * temp = strtok_r(contentfield, ARGUMENTSEPARATOR, &content);
		counter++;

		struct queryvals query = {CONTENTQUERY, ""};
		addtoquery(query.values, addapos(content));
		addtoquery(query.values, contenttohex(content));
		addtoquery(query.values, contenttohex(nocase(content)));

		addmodifiers(query.values, save);

		char countstring[LINESIZE] = "\0";
		sprintf(countstring, "%d", counter);

		addtoquery(query.values, countstring);
		addtoquery(query.values, sidsave);
		addtoquery(query.values, revsave);

		char statement[STATEMENTSIZE];
		strcpy(statement, createquerystatement(query, CONTENTTABLE));
	
		if (mysql_query(conn, statement) == 1) {
			mysqlerror(conn);
		}

		helper += (strlen(temp) + strlen(content) + 2);
	}
}

int getRules (char DATABASE[], MYSQL * conn) {
	FILE * rules;
	char line[LINESIZE];			//String to hold individual lines from rule file 
	
	rules = fopen(RULEFILE, "r");		//Opening rule file as read-only

	if (rules == NULL) {
		printf("Failed to load rules.\n");
		return 2;
	}

	if (conn == NULL) {
		mysqlerror(conn);
	}

	while (fgets(line, LINESIZE, rules) != NULL) {
		struct queryvals query = { "action, protocol, sourceip, sourceport, direction, destip, destport", "" };
		
		if (line[0] != '#' && !isempty(line)) {
			getcontent(conn, line);
			char lineholder[LINESIZE];
			strcpy(lineholder, line);
			char * saveptr = line;
			char * temp = strtok_r(saveptr, HEADERSEPARATOR, &saveptr);
			
			for (int i = 0; i < NUMRULEHEADERS; i++) {
				addtoquery(query.values, temp);
				temp = strtok_r(saveptr, HEADERSEPARATOR, &saveptr);
			}
			
			addtoquery(query.values, temp);
			temp = strtok_r(saveptr, OPTIONSSEPARATOR, &saveptr);
			
			while (temp != NULL) {
				query = getruleoption(query, temp, saveptr);	
				temp = strtok_r(saveptr, OPTIONSSEPARATOR, &saveptr);
			}

			char statement[STATEMENTSIZE];
			strcpy(statement, createquerystatement(query, RULETABLE));

			if (mysql_query(conn, statement) == 1) {
				mysqlerror(conn);
			}
		}
	}

	fclose(rules);		//Closing rule file

	return 0;
}


