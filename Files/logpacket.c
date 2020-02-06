#include "logpacket.h"

#define FILENAMESIZE 512	//Maximum size for a file name
#define BUFFER 4096		
#define LOGDIRNAME "Logs"	//Folder that contains log files
#define EMAILS "emails.txt"
#define EXTENSIONLEN 4

//Checks if a folder exists, and creates it if it doesn't
void checkfolder (char location[]) {
	struct stat st = {0};

	if (stat(location, &st) == -1) {
		mkdir(location, 0755);
	}
}

//Sends email to specified addresses
void sendemail (char filename[]) {
	FILE * emails;
	char line[BUFFER];
	emails = fopen(EMAILS, "r");

	if (emails == NULL) {
		printf("Failed to open email files.\n");
		return;
	}

	//Runs the sendmail command for every email address in the file
	while (fgets(line, BUFFER, emails) != NULL) {
		if (line[0] != '#' && line[0] != '\n') {
			char cmd[BUFFER];
			line[strcspn(line, "\n")] = 0;
			snprintf(cmd, BUFFER, "sendmail %s < %s", line, filename);
			system(cmd);
		}
	}

	fclose(emails);
}

//Creates a log file for malicious packets for each day and adds to file for every malicious packet found that day
void createlog (char msg[], char source[], char dest[], int sourceport, int destport, const char payload[]) {
	char filename[FILENAMESIZE] = "\0";
	time_t t = time(NULL);
	struct tm date = *localtime(&t);

	//Log file name is dependent on the day
	snprintf(filename + strlen(filename), FILENAMESIZE, "Logs/Logs-%d-%d-%d", date.tm_mon + 1, date.tm_mday, date.tm_year + 1900);

	checkfolder(filename);
	
	char temp[FILENAMESIZE];
	char numfile[FILENAMESIZE];

	int count = 1;

	//Creates incrementing file names (log1, log2, log3, ...)
	do {
		snprintf(numfile, FILENAMESIZE, "/log%d", count);
		snprintf(temp, FILENAMESIZE, "Logs/Logs-%d-%d-%d%s", date.tm_mon + 1, date.tm_mday, date.tm_year + 1900, numfile);
		count++;
	} while (access(temp, F_OK) != -1);

	snprintf(filename + strlen(filename), FILENAMESIZE, "%s", numfile);

	//Open the file to append 
	FILE * log;
	log = fopen(filename, "a");

	if (log == NULL) {
		printf("Failed to open log file");
		return;
	}

	//Prints information into file
	fprintf(log, "Subject: Malicious activity found\n");
	fprintf(log, "Date - %d/%d/%d\nTime - %d:%d:%d\n\n", date.tm_mon + 1, date.tm_mday, date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, msg, source, dest);
	fprintf(log, "Rule: %s\n\n", msg);
	fprintf(log, "Source IP: %s\n", source);
	fprintf(log, "Source Port: %d\n\n", sourceport);
	fprintf(log, "Destination IP: %s\n", dest);
	fprintf(log, "Destination Port: %d\n\n", destport);
	fprintf(log, "Payload: %s\n", payload);
	fclose(log);

	sendemail(filename);
}
