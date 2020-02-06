//This file handles seaching through the packet payload and comparing it to all rules

#include "scanpacket.h"
#include "boyermoore.h"
#include "logpacket.h"

#define CONTENTSEPARATOR ','
#define PORTSEPARATOR ","
#define CONTENTINDICATOR '"'
#define MUSTCONTAIN '!'
#define SPACE ' '
#define BINARYSEPARATOR "|"
#define CONTENTSIZE 1024
#define IPSIZE 256
#define PORTSIZE 64
#define QUERYSIZE 256
#define PACKETSIZE 4096
#define BASE 10
#define $HOME_NET "any"
#define $EXTERNAL_NET "any"
#define $DNS_SERVERS "any"
#define $SMTP_SERVERS "any"
#define $HTTP_SERVERS "any"
#define $SQL_SERVERS "any"
#define $TELNET_SERVERS "any"
#define $SSH_SERVERS "any"
#define $FTP_SERVERS "any"
#define $SIP_SERVERS "any"

//The follow are the location of variables in the array returned by mysql 
#define CONTENTPOS 0
#define HEXCONTENT 1
#define LOWERHEXCON 2
#define NOCASEPOS 3
#define SIDPOS 4
#define COUNTPOS 5
#define HTTPCBPOS 6
#define HTTPRCPOS 7
#define HTTPHEADPOS 8
#define HTTPRHEADPOS 9
#define HTTPMETHPOS 10
#define HTTPURIPOS 11
#define HTTPRURIPOS 12
#define HTTPSCODEPOS 13
#define HTTPSMSGPOS 14
#define HTTPCOOKPOS 15
#define FASTPATPOS 16
#define WITHINPOS 17
#define DEPTHPOS 18
#define OFFSETPOS 19
#define DISTPOS 20

//Uses boyer-moore to search packet for given content, returns position where content starts in packet
int searchforcontent (const char * packet, const char * content) {
	if (bm(packet, content) == -1) {
		return 0;
	} 

	return 1;
}

//Compares ports from rule and packet to see if they match, returns 1 if there is a match, 0 if not
int getports (MYSQL * conn, char ruleport[], int port) {
	if (strcmp(ruleport, "any") == 0) {
		return 1;
	} else if (strtol(ruleport, NULL, 10) == port) {
		return 1;
	} else if (ruleport[0] == '[') {
		char copy[PORTSIZE];
		strcpy(copy, ruleport);

		char * portlist = copy;
		portlist[strlen(portlist)] = '\0';
		portlist++;

		char * save;
		char * p = strtok_r(portlist, PORTSEPARATOR, &save);

		while (p != NULL) {
			if (strtol(p, NULL, 10) == port) {
				return 1;
			}
			
			p = strtok_r(save, PORTSEPARATOR, &save);
		}

		return 0;
	}		

	char query[QUERYSIZE] = "\0";
	snprintf(query + strlen(query), QUERYSIZE, "SELECT port, required FROM ports WHERE varname = '%s';", ruleport);

	if (mysql_query(conn, query)) {
		mysqlerror(conn);
	}

	MYSQL_RES * portresults = mysql_store_result(conn);
	if (portresults == NULL) {
		mysqlerror(conn);
		mysql_free_result(portresults);
		return -1;
	}

	MYSQL_ROW row;

	while (row = mysql_fetch_row(portresults)) {
		char portstring[QUERYSIZE] = "\0";
		snprintf(portstring + strlen(portstring), QUERYSIZE, "%d", port);

		if ((row[1] == "1" && portstring != row[0]) || (row[0] == portstring && row[1] == "0")) {
			mysql_free_result(portresults);
			return 1;
		}
	}
	
	mysql_free_result(portresults);
	return 0;
}

//Compares ip and ports from rule to those from the packet
int compareaddress (MYSQL * conn, const struct sniff_ip * ip, const struct sniff_tcp * tcp, const char * sid) {
	char sourceip[IPSIZE] = "\0", destip[IPSIZE] = "\0"; //Holds ips from packet
	char query[QUERYSIZE] = "\0"; //String to hold query to obtain rule ip and ports
	int sourceport, destport;
	
	//Copies ips and ports from packet 
	strcpy(sourceip, inet_ntoa(ip->ip_src));
	strcpy(destip, inet_ntoa(ip->ip_dst));
	sourceport = tcp->th_sport;
	destport = tcp->th_dport;

	//Create query to get ips and ports of rule specified by given sid
	snprintf(query + strlen(query), QUERYSIZE, "SELECT sourceip, sourceport, direction, destip, destport FROM rules WHERE sid = %s;", sid);

	if (mysql_query(conn, query)) {
		mysqlerror(conn);
		return -1; 
	}

	MYSQL_RES * headerresult = mysql_store_result(conn);

	if (headerresult == NULL) {
		mysqlerror(conn);
		mysql_free_result(headerresult);
		return -1;
	}

	MYSQL_ROW ruleheader;
	
	//Compares ports of rule to ports of packet
	while (ruleheader = mysql_fetch_row(headerresult)) {
		if (getports(conn, ruleheader[1], sourceport) && getports(conn, ruleheader[4], destport)) {
			mysql_free_result(headerresult);
			return 1;
		}		
	}

	mysql_free_result(headerresult);

	return 0;
}	

//Handles depth content modifier
void depthstring (char payload[], int depth) {
	payload[depth] = '\0';
}

//Handles offset content modifier
void offsetstring (char payload[], int offset) {
	char * temp = payload;
	temp += offset;
	strcpy(payload, temp);
}

//Handles distance content modifier
void distancestring (const char prevcontent[], char payload[], int distance) {
	if (prevcontent) {
		char * temp = strstr(payload, prevcontent);
		temp += strlen(prevcontent) + distance;
		strcpy(payload, temp);
	}
}

//Handles within content modifier
void withinstring (const char prevcontent[], char payload[], int within) {
	if (prevcontent) {
		char * temp = strstr(payload, prevcontent);
		temp += strlen(prevcontent);
		strcpy(payload, temp);
		payload[within] = '\0';
	}
}

//Searches the payload for rules
int searchpayload (MYSQL * conn, const struct sniff_ip * ip, const struct sniff_tcp * tcp, MYSQL_ROW row, const char payload[], const char hexpayload[], const char lowerhex[], char * prevcontent) {
	char payloadcopy[PACKETSIZE] = "\0", hexcopy[PACKETSIZE] = "\0";
	char * helper;

	strcpy(payloadcopy, payload);

	if (strcmp(row[NOCASEPOS], "1") == 0) {
		strcpy(hexcopy, lowerhex);
		helper = row[LOWERHEXCON];
	} else {
		strcpy(hexcopy, hexpayload);
		helper = row[HEXCONTENT];
	}

	int offset = strtol(row[OFFSETPOS], NULL, BASE);
	int depth = strtol(row[DEPTHPOS], NULL, BASE); 
	int distance = strtol(row[DISTPOS], NULL, BASE);
	int within = strtol(row[WITHINPOS], NULL, BASE);

	if (offset > 0) {
		offsetstring(hexcopy, offset * 3);
	}

	if (depth > 0) {
		depthstring(hexcopy, depth * 3);
	}
	
	if (distance > 0) {
		distancestring(prevcontent, hexcopy, distance * 3);
	}

	if (within > 0) {
		withinstring(prevcontent, hexcopy, within * 3);
	}

	if (row[CONTENTPOS][0] == MUSTCONTAIN) {
		if (!searchforcontent(hexcopy, helper) && compareaddress(conn, ip, tcp, row[SIDPOS])) {
			return 1;
		} else {
			return 0;
		}

	} else {
		if (searchforcontent(hexcopy, helper) && compareaddress(conn, ip, tcp, row[SIDPOS])) {
			prevcontent = helper;
			return 1;
		} else {
			return 0;
		}
	}				
}

//If a packet is found to be malicious, this will store it into a log file
void storeinfo (const struct sniff_ip * ip, const struct sniff_tcp * tcp, MYSQL_ROW row, const char payload[]) {

	char sourceip[IPSIZE] = "\0", destip[IPSIZE] = "\0";
	int sourceport = tcp->th_sport;
	int destport = tcp->th_dport;
	
	strcpy(sourceip, inet_ntoa(ip->ip_src));
	strcpy(destip, inet_ntoa(ip->ip_dst));

	createlog(row[0], sourceip, destip, sourceport, destport, payload);
}

int scan (const char * payload, const char * hexpayload, const char * lowerhex, const struct sniff_ip * ip, const struct sniff_tcp * tcp, MYSQL * conn) {
	//Gets only the first content field in all rules
	//If the first isn't found, the rest won't matter
	if (mysql_query(conn, "SELECT * FROM content WHERE contentcount = 1;")) {
		mysqlerror(conn);
		return -1;
	}

	MYSQL_RES * contentresult = mysql_store_result(conn);				
	
	if (contentresult == NULL) {
		mysqlerror(conn);
		return -1;
	}

	MYSQL_ROW row;		
		
	char * prev = NULL;

	//Goes through every row that was returned by the query
	while (row = mysql_fetch_row(contentresult)) {
		int run = 1;
		char id[512] = "\0";
		strcpy(id, row[SIDPOS]);
		//If the first content field of the rule was found, search for any others
		if (searchpayload(conn, ip, tcp, row, payload, hexpayload, lowerhex, prev)) {
			char query[QUERYSIZE];
			memset(query, '\0', sizeof(query));
			snprintf(query + strlen(query), QUERYSIZE, "SELECT * FROM content WHERE sid = %s AND contentcount != 1;", row[SIDPOS]);
		
			if (mysql_query(conn, query)) {
				mysqlerror(conn);
				return -1;	
			}
		
			MYSQL_RES * queryresult = mysql_store_result(conn);
	
			if (queryresult == NULL) {
				mysqlerror(conn);
				return -1;
			}
			
			//If any other content for the rule isn't found, the packet is safe
			while (row = mysql_fetch_row(queryresult)) {
				if (!searchpayload(conn, ip, tcp, row, payload, hexpayload, lowerhex, prev)) {
					run = 0;
				}
			}
			
			mysql_free_result(queryresult);
			
			//If all remaining content fields of the rule were found
			if (run) {
				mysql_free_result(contentresult);
			 	char msgquery[QUERYSIZE] = "\0";
				//Gets rule message to put into log file
				snprintf(msgquery + strlen(msgquery), QUERYSIZE, "SELECT msg FROM rules WHERE sid = %s", id);
			
				if (mysql_query(conn, msgquery)) {
					mysqlerror(conn);
					return -1;
				}

				MYSQL_RES * rulemessage = mysql_store_result(conn);

				if (rulemessage == NULL) {
					mysqlerror(conn);
					return -1;
				}

				row = mysql_fetch_row(rulemessage);

				printf("Log intrusion\n\n");
				
				//Put information into file
				storeinfo(ip, tcp, row, payload);
				
				//Clear mysql results and return
				mysql_free_result(rulemessage);
				return 1;				
			}
		}

		prev = NULL;
	} 	
	 	
	//Packet is safe if it made it down here, clear results and return
	printf("Packet clear\n\n");
	mysql_free_result(contentresult);

	return 0;
}
