#include "packetsniff.h"
#include "scanpacket.h"
#include "readrules.h"
#include "port.h"
#include "startup.h"

#define HOST "localhost"	//Host to use for mysql
#define USER "root"		//User for mysql
#define PASSWORD "raspberry"	//Password for mysql
#define DATABASE "IDS"		//Database for mysql

//Columns for the content table
#define CONTENTFIELDS "content VARCHAR(2048), hexcontent TEXT, lowerhexcontent TEXT, nocase CHAR(1), sid INT, contentcount INT, httpclientbody CHAR(1), httprawcookie CHAR(1), httpheader CHAR(1), httprawheader CHAR(1), httpmethod CHAR(1), httpuri CHAR(1), httprawuri CHAR(1), httpstatcode CHAR(1), httpstatmsg CHAR(1), httpcookie CHAR(1), fastpattern VARCHAR(1024), within VARCHAR(1024), depth VARCHAR(1024), offset VARCHAR(1024), distance VARCHAR(1024), rev INT, PRIMARY KEY (sid, contentcount, rev)"

//Columns for the rule table
#define RULEFIELDS "action VARCHAR(10), protocol VARCHAR(10), sourceip VARCHAR(50), sourceport VARCHAR(20), direction VARCHAR(5), destip VARCHAR(50), destport VARCHAR(20), msg VARCHAR(256), reference TEXT, gid INT, sid INT, rev INT, classtype TEXT, priority INT, metadata TEXT, protected_content TEXT, hash VARCHAR(20), length INT, rawbytes CHAR(1), http_encode TEXT, uricontent TEXT, urilen TEXT, isdataat TEXT, pcre TEXT, pkt_data CHAR(1), file_data CHAR(1), base64_decode TEXT, base64_data TEXT, byte_test TEXT, byte_jump TEXT, byte_extract TEXT, byte_math TEXT, ftpbounce CHAR(1), asn1 TEXT, cvs TEXT, dce_iface TEXT, dce_opnum TEXT, dce_stub_data TEXT, sip_method TEXT, sip_stat_code TEXT, sip_header TEXT, sip_body TEXT, gtp_type TEXT, gpt_info TEXT, gtp_version TEXT, ssl_version TEXT, ssl_state TEXT, fragoffset TEXT, ttl TEXT, tos TEXT, id INT, ipopts TEXT, fragbits TEXT, dsize TEXT, flags TEXT, flow TEXT, flowbits TEXT, seq INT, ack INT, window INT, itype TEXT, icode TEXT, icmp_id INT, icmp_seq INT, rpc TEXT, ip_proto TEXT, sameip CHAR(1), stream_reassemble TEXT, stream_size TEXT, logto TEXT, session TEXT, resp TEXT, react TEXT, tag TEXT, rep TEXT, detection_filter TEXT, PRIMARY KEY (sid, rev)"

//Columns for the port table
#define PORTFIELDS "varname VARCHAR(100), port INT, required CHAR(1), PRIMARY KEY (varname, port)" 

#define SIZE_ETHERNET 14	//Maximum size of ethernet header
#define BUFFER 1024		//Buffer size
#define QUERYSIZE 2048		//Maximum size of query for mysql

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

//Prints error for mysql if anything fails
void mysqlerror (MYSQL * conn) {
	fprintf(stderr, "%s\n", mysql_error(conn)); 
}

//Closes the connection to the mysql database
void closemysql(MYSQL * conn) {
	mysql_close(conn);
	mysql_library_end();
}

//Function to run when packet is captured
void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const struct sniff_udp *udp;
	const char *payload;
	
	int size_ip;
	int size_tcp;
	int size_udp;
	int size_icmp;
	int size_payload;
	
	MYSQL * conn = (MYSQL *)args;

	ethernet = (struct sniff_ethernet*)(packet);

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

	if (size_ip < 20) {
		printf("Invalid IP header length: %u bytes\n", size_ip);
	}

	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	//Prints source and destination ip and port
	printf("From: %s:%d\n", inet_ntoa(ip->ip_src), tcp->th_sport);
	printf("To: %s:%d\n", inet_ntoa(ip->ip_dst), tcp->th_dport);

	//These strings will hold the payload from the packet
	//Two for the payload in hex (one in lowercase for comparision with the nocase flag)
	//asciidata string holds the payload as ascii characters
	char hexdata[(header->len * 3) + 1];
	char nocasehex[(header->len * 3) + 1];
	char asciidata[header->len + 1];
	
	//Empty strings
	memset(hexdata, '\0', sizeof(hexdata));
	memset(nocasehex, '\0', sizeof(nocasehex));
	memset(asciidata, '\0', sizeof(asciidata));

	//Puts printable ascii characters into string
	//If the character is not printable, a period is used
	for (int i = 0; i < header->len; i++) {
		if (isprint(payload[i])) {
			asciidata[i] = payload[i];
		} else {
			asciidata[i] = '.';
		}
		
		asciidata[header->len + 1] = '\0';	
	}
		
	//Fills the two hex payload strings
	for (int i = 0; i < header->len; i++) {
		snprintf(hexdata + strlen(hexdata), BUFFER, "%02x", *payload);			
		snprintf(nocasehex + strlen(nocasehex), BUFFER, "%02x", tolower(*payload));

		if (i != header->len - 1) {
			strcat(hexdata, " ");
			strcat(nocasehex, " ");
		}

		payload++;
	}

	printf("%s\n", asciidata);

	//Sends packet data to scan function to be searched for any malicious content
	scan(asciidata, hexdata, nocasehex, ip, tcp, conn);
}

//Creates database tables if they do not exist
void checktables (MYSQL * conn) {
	char query[QUERYSIZE] = "\0";

	//Query for content table
	snprintf(query + strlen(query), QUERYSIZE, "CREATE TABLE IF NOT EXISTS content (%s);", CONTENTFIELDS);

	if (mysql_query(conn, query)) {
		mysqlerror(conn);
	}

	//Query for rules table
	memset(query, '\0', sizeof(query));
	snprintf(query + strlen(query), QUERYSIZE, "CREATE TABLE IF NOT EXISTS rules (%s);", RULEFIELDS);
	
	if (mysql_query(conn, query)) {
		mysqlerror(conn);
	}	
	
	//Query for ports table
	memset(query, '\0', sizeof(query));
	snprintf(query + strlen(query), QUERYSIZE, "CREATE TABLE IF NOT EXISTS ports(%s);", PORTFIELDS);
	
	if (mysql_query(conn, query)) {
		mysqlerror(conn);
	}
}

//Checks if the database exists
int checkfordatabase (MYSQL * conn) {
	char query[QUERYSIZE] = "\0";
	snprintf(query + strlen(query), QUERYSIZE, "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '%s';", DATABASE);

	if (mysql_query(conn, query)) {
		mysqlerror(conn);
	}

	MYSQL_RES * result = mysql_store_result(conn);
	MYSQL_ROW row = mysql_fetch_row(result);

	mysql_free_result(result);

	if (row == NULL) {
		return 1;
	}

	return 0;
}

int main() {
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net;
	bpf_u_int32 mask;
	struct bpf_program fp;
	const u_char *packet;
	struct pcap_pkthdr header;

	initialstart();

	MYSQL * conn = mysql_init(NULL);
	pcap_t * handle;

	if (conn == NULL) {
		mysqlerror(conn);
	}

	//Connection to mysql
	if (mysql_real_connect(conn, HOST, USER, PASSWORD, NULL, 0, NULL, 0)) {
		char query[QUERYSIZE] = "\0";

		int createddb = 0;

		//Checks if database exists and creates it if it doesn't
		if (checkfordatabase(conn)) {
			snprintf(query + strlen(query), QUERYSIZE, "CREATE DATABASE IF NOT EXISTS %s;", DATABASE);
			
			printf("Creating database...\n");
		 	if (mysql_query(conn, query)) {
				mysqlerror(conn);
			}

			createddb = 1;
		}
		
		memset(query, '\0', sizeof(query));
		snprintf(query + strlen(query), QUERYSIZE, "USE %s;", DATABASE);

		if (mysql_query(conn,query)) {
			mysqlerror(conn);
		}

		//If the database was just created, create the tables as well
		if (createddb) {
			printf("Creating database tables...\n");
			checktables(conn);
			printf("Reading rules from file...\n");
			getRules(DATABASE, conn);
		}

		printf("Reading ports from file...\n");
		getPorts(DATABASE, conn);

		//Looks for device 
		dev = pcap_lookupdev(errbuf);

		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}

		if (pcap_lookupnet(dev, &net, &mask, errbuf) == 1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			return(2);
		}		

		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}

		//Set promiscious mode to true so we can get all traffic
		pcap_set_promisc(handle, 1);

		printf("Listening on device %s.\n\n", dev);

		//Loops indefinitely searching for packets and sending the to the gotPacket function where they are searched through
		pcap_loop(handle, 0, gotPacket, (u_char*)conn);

		pcap_close(handle);
	} else {
		mysqlerror(conn);
	}
	
	closemysql(conn);
	
	return 0;
}
