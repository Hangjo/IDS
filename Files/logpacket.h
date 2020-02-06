#ifndef logpacket
#define logpacket

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

void createlog (char msg[], char source[], char dest[], int sourceport, int destport, const char payload[]);

#endif
