#include "boyermoore.h"

#define CHAR_DIF 48 		//Char to int
#define PATTERN_CHAR_SIZE 74	

int * last (const char pattern[]) {
	static int list[PATTERN_CHAR_SIZE] = {0};

	for (int i = strlen(pattern) - 1; i >= 0; i--) {
		if (i > list[(int)pattern[i] - CHAR_DIF]) {
			list[(int)pattern[i] - CHAR_DIF] = i;
		}
	}

	return list;
}

int bm (const char string[], const char pattern[]) {
	int m = strlen(pattern);
	int n = strlen(string);
	
	int * lastpos;
	lastpos = last(pattern);

	int j = m - 1;
	int i = j;

	while (i < n) {
		if (pattern[j] == string[i]) {
			if (j == 0) {
				return i;
			} else {
				i--;
				j--;
			}
		} else {
			i = i + m - fmin(j, 1 + lastpos[(int)string[i] - CHAR_DIF]);
			j = m - 1;
					
		}
	}
	
	return -1;
}
