#include "startup.h"

#define BUFFER 4096
#define CRONFILE "Cron"		//Name of the file with the cron job
#define LOGDIRECTORY "Logs"	//Name of the folder that holds logs
#define EMAILS "emails.txt"	//Name of the file containing list of emails to send alerts to
#define PORTS "ports.txt"	//Name of the file containing list of ports

//Installs all necessary applications for this program
void install () {
	char update[] = "apt-get update";
	system(update);

	char upgrade[] = "apt-get upgrade";
	system(upgrade);

	char installmysql[] = "apt-get install mysql-server";
	system(installmysql);

	char installmail[] = "apt-get install sendmail";
	system(installmail);
}

//Creates cron job to download new rules file every morning at 6 a.m. and run the update program
void cronjob () {
	FILE * job;
	job = fopen(CRONFILE, "w");

	if (job == NULL) {
		printf("Failed to create cronjob\n");
		return;
	}
	
	char cwd[BUFFER];
	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		printf("Failed to create cron job.\n");
		return;
	}

	char cmd[BUFFER];
	snprintf(cmd, BUFFER, "0 6 * * * cd %s && /usr/bin/wget -O i %s/rules.tar.gz https://www.snort.org/downloads/community/community-rules.tar.gz && /bin/tar -xvzf rules.tar.gz && /bin/mv %s/community-rules/community.rules %s && /bin/rm rules.tar.gz && /bin/rm -r community-rules && /bin/chmod u=rw,g=rw,o=rw community.rules && ./updatedb\n", cwd, cwd, cwd, cwd);

	fprintf(job, "%s", cmd);

	fclose(job);	

	char crontab[BUFFER];
	snprintf(crontab, BUFFER, "sudo crontab -u root %s", CRONFILE);

	system(crontab);
}

//Creates folder to hold logs in the same directory as the program
void createlogfolder () {
	mkdir(LOGDIRECTORY, 0755);
}

void createfiles () {
	FILE * email;

	email = fopen(EMAILS, "a");

	if (email == NULL) {
		printf("Failed to create emails file.\n");
		return;
	}	

	fprintf(email, "# This file contains the list of addresses to be sent an alert\n");
	fprintf(email, "# Each email address must be on its own line");
}

void downloadrules () {
	char cwd[BUFFER];

	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		printf("Failed to download rules file");
		return;
	}

	char cmd[BUFFER];
	snprintf(cmd, BUFFER, "cd %s", cwd);
	system(cmd);
	snprintf(cmd, BUFFER, "/usr/bin/wget -O %s/rules.tar.gz https://www.snort.org/downloads/community/community-rules.tar.gz", cwd);
	system(cmd);
	snprintf(cmd, BUFFER, "/bin/tar -xvzf rules.tar.gz");
	system(cmd);
	snprintf(cmd, BUFFER, "/bin/mv %s/community-rules/community.rules %s", cwd, cwd);
	system(cmd);
	snprintf(cmd, BUFFER, "/bin/rm rules.tar.gz");
	system(cmd);
	snprintf(cmd, BUFFER, "/bin/rm -r community-rules");
	system(cmd);
	snprintf(cmd, BUFFER, "/bin/chmod u=rw,g=rw,o=rw community.rules");
	system(cmd);
}

//Creates all files and installations if the Logs folder hasn't been created
void initialstart () {
	struct stat st = {0};

	if (stat(LOGDIRECTORY, &st) == -1) {
		install();
		cronjob();
		createlogfolder();
		createfiles();
		downloadrules();
	}
}
