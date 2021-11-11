#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <regex.h>
#include <unistd.h>

#include <ncurses.h>

// TODO(feature): Auto window-resizing.
// TODO(feature): Support for greppable output.

#define NMAP_HEADER "Starting Nmap "

struct OpenIP {
	char** open;
	size_t* sizes;
	size_t openCnt;
};

void
finish(struct OpenIP oi, int status) {
	if (status > -4) {
		/* If error occured after ncurses was initialized. */
		curs_set(1);
		clear();
		refresh();
		resetty();
		endwin();
	}

	switch(status) {
		case -1: fprintf(stderr, "nmaptrix err: All ports are closed.\n");
		case -2: fprintf(stderr, "nmaptrix err: Your terminal does not support colors.\n");
		case -3: fprintf(stderr, "nmaptrix err: Terminal window is too narrow.\n");
		case -4: fprintf(stderr, "nmaptrix err: Nmap header was not found.\n");
		case -5: fprintf(stderr, "nmaptrix err: Regex failed to compile.\n");
	}
	
	free(oi.open);
	free(oi.sizes);
	exit(0);
}

void
genRandom(int16_t* padding, int16_t* startOffset, uint16_t xMax, 
			uint16_t yMax, struct OpenIP oi)
{
	for (int i = 0; i < xMax; i++) {
		int ii = (i < oi.openCnt) ? i : i % oi.openCnt;
		padding[i] = rand() % (yMax - oi.sizes[ii]);
		startOffset[i] = rand() % 5;
	}
}

void
createMatrix(struct OpenIP oi, uint16_t xMax, uint16_t yMax) {
	if (!oi.openCnt || !xMax || !yMax) 		// Sanity check.
		finish(oi, -1);
	
	if (oi.openCnt > xMax)
		finish(oi, -3);

	init_pair(COLOR_BLACK, -1, -1);
	init_pair(COLOR_GREEN, COLOR_GREEN, -1);

	int16_t padding[xMax], startOffset[xMax];

	genRandom(padding, startOffset, xMax, yMax, oi);
	
	for (int8_t cursor = 0; ; cursor++) {
		uint16_t completed = 0;
		
		for (int i = 0; i < xMax; i++) {
			/* Populate the row. */

			uint16_t startPad = (startOffset[i] + padding[i]);

			int ii = (i < oi.openCnt) ? i : i % oi.openCnt;

			if ((cursor >= startPad) && (oi.sizes[ii] > (cursor - startPad))) {
				attron(A_BOLD);
				mvaddch(cursor - startOffset[i], i, oi.open[ii][cursor - startPad]);
				attroff(A_BOLD);
			} else if (oi.sizes[ii] < (cursor - startPad))
				completed++;

			if ((oi.sizes[ii] >= (cursor - startPad) && ((cursor - startPad) != 0))) {
				/* Set the previous character displayed to green. */

				attron(A_BOLD);
				attron(COLOR_PAIR(COLOR_GREEN));
				mvaddch(cursor - startOffset[i] - 1, i, 
						oi.open[ii][cursor - startPad - 1]);
				attroff(COLOR_PAIR(COLOR_GREEN));
				attroff(A_BOLD);
			}
		}

		refresh();
		napms(100);

		if (completed == xMax) {
			clear();
			cursor = 0;
			genRandom(padding, startOffset, xMax, yMax, oi);	
		}
	}
}

struct OpenIP
parseNmap(uint16_t max) {

	/* 
		Brute-force matching nmap output in search
		of specific lines showing open ports. 
	*/

	struct OpenIP oi = {0};
	oi.open = (char**)malloc(max * sizeof(char*));
	oi.sizes = (size_t*) malloc(max * sizeof(size_t));

	char buf[256] = {0};

	regex_t reg[2];			// regex_t for both ipReg and portReg.
	regmatch_t ipMatch[2];
	regmatch_t portMatch[2];

	int ipReg = regcomp(&reg[0], "^Nmap scan report for ([[:digit:]\\:\\.]+)",
						REG_EXTENDED);
	int portReg = regcomp(&reg[1], "^([[:digit:]]+\\/[tcpud]+)[[:blank:]]+open", REG_EXTENDED);

	fgets(buf, 256, stdin);

	if (strncmp(buf, NMAP_HEADER, 14) != 0) {
		regfree(&reg[0]);
		regfree(&reg[1]);
		finish(oi, -4);
	}

	if (ipReg || portReg) {
		regfree(&reg[0]);
		regfree(&reg[1]);
		finish(oi, -5);
	}
	
	while (fgets(buf, 256, stdin)) {
		if (oi.openCnt == max)		// Terminal breaks if stdin isn't flushed.
			continue;

		ipReg = regexec(&reg[0], buf, 2, ipMatch, 0);

		if (ipReg == 0) {
			size_t ip, port;
			size_t cursor = 0;
			char temp[256] = {0};

			for (int i = ipMatch[1].rm_so; i < ipMatch[1].rm_eo; i++) 
				temp[cursor++] = buf[i];

			fgets(buf, 256, stdin);
			fgets(buf, 256, stdin);
			fgets(buf, 256, stdin);
			
			if (buf[0] == '\n')			// All ports closed.
				continue;

			for (fgets(buf, 256, stdin); buf[0] != '\n'; fgets(buf, 256, stdin)) {
				portReg = regexec(&reg[1], buf, 2, portMatch, 0);

				ip = ipMatch[1].rm_eo - ipMatch[1].rm_so;
				port = portMatch[1].rm_eo - portMatch[1].rm_so;

				if (portReg != 0)
					continue;

				oi.sizes[oi.openCnt] = ip + port + 1;
				oi.open[oi.openCnt] = (char*)malloc(oi.sizes[oi.openCnt]);

				strncpy(oi.open[oi.openCnt], temp, ip);
				oi.open[oi.openCnt][ip++] = ':';
				
				for (int i = 0; i < port; i++)
					oi.open[oi.openCnt][ip++] = buf[i];
				
				oi.openCnt++;

				if (oi.openCnt == max)
					break;
			}

		} else if (ipReg == REG_NOMATCH)
			continue;
	}

	regfree(&reg[0]);
	regfree(&reg[1]);
	return oi;

}

uint16_t
argumentHandler(int argc, char** argv) {
	/* 
		Barebones command line arguement handling. 
		None of that fancy fullword/mutli-argument nonsense here.
	*/

	uint16_t maxNum = 100;

	if (argc == 1 || argv[1][0] != '-') 
		return maxNum;

	switch (argv[1][1]) {
		case 'm': 
			maxNum = (uint16_t)atoi(argv[1]+2);
			break;
		default:
			printf("There is only one command line argument:\n");
			printf("\tMax Number of open ports to check: -m[int]\n");
			return 0;
	}

	return maxNum;
}

int
main(int argc, char** argv) {
	uint16_t maxNum = argumentHandler(argc, argv);

	if (maxNum == 0)
		return 0;
	
	if (isatty(0)) {
		fprintf(stderr, "nmaptrix err: nmaptrix is meant to be piped to by nmap; ");
		fprintf(stderr, "it is not a standalone program!\n");
		return -1;
	}

	srand((unsigned)time(NULL));

	struct OpenIP oi = parseNmap(maxNum);

	// Initialize ncurses.
	initscr();
	savetty();

	if (!has_colors() || (use_default_colors() == ERR)) 
		finish(oi, -2);

	noecho();
	cbreak();
	timeout(0);
	curs_set(0);
	start_color();

	init_pair(COLOR_BLACK, -1, -1);
	init_pair(COLOR_GREEN, COLOR_GREEN, -1);

	uint16_t xMax, yMax;
	getmaxyx(stdscr, yMax, xMax);

	createMatrix(oi, xMax, yMax);

	finish(oi, 0);

	return 0;
}
