#include <stdio.h>
#include <stdint.h>
#include <pthread.h> 
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <signal.h>

#include <ncurses.h>

#include "cli.h"
#include "dns.h"

#define BUFF_SZ 1024
#define MSG_SZ 2048
#define COLOR_REPLY 1
#define COLOR_QUERY 2

#define HELP_MSG "Press 'q' to quit, 'r' to send request, 'p' to pause/resume, 'c' to clear screen"

extern int efd;
volatile sig_atomic_t terminal_resized = 0;
static WINDOW *result;
static WINDOW *query;
static WINDOW *help;
static WINDOW *status;

uint8_t requestbuf[BUFF_SZ] = {0};

static void
handle_resize(int signal)
{
    terminal_resized = 1;
}

void
printToWindow(const char *format, ...)
{
    int lines = 0;
    const char *nline = NULL;
    va_list args;

    nline = strchr(format, '\n');
    while (nline != NULL) {
        lines++;
        nline = strchr(nline + 1, '\n');
    }
    wmove(result, 0, 0);
    winsdelln(result, lines);

    va_start(args, format);
    vw_printw(result, format, args);
    va_end(args);
    wrefresh(result);
}

void
printToWindow_(const char *msg)
{
    int lines = 0;
    const char *nline = NULL;
    int color_pair = 0;
    if (result == NULL) {
        goto out;
    }

    if (strstr(msg, " Reply:") != NULL) {
        color_pair = COLOR_PAIR(COLOR_REPLY);
    } else if (strstr(msg, " Query:") != NULL) {
        color_pair = COLOR_PAIR(COLOR_QUERY);
    }

    nline = strchr(msg, '\n');
    while (nline != NULL) {
        lines++;
        nline = strchr(nline + 1, '\n');
    }

    wmove(result, 0, 0);
    winsdelln(result, lines);
    if (color_pair != 0) {
        wattron(result, color_pair);
    }
    mvwprintw(result, 0, 0, "%s", msg);
    if (color_pair != 0) {
        wattroff(result, color_pair);
    }
    wrefresh(result);

out:
    return;
}

void *
interactive(void *arg)
{
    uint64_t signal = 0;
    uint16_t buflen = 0;
    uint16_t i = 0;
    uint8_t start = 0;
    DNSPacket *dnsPacket = NULL;
    int key = 0;
    struct winsize terminal_size;
    int rows = 0;
    int columns = 0;
    bool isPaused = false;
    
    initscr();
    cbreak();
    noecho();
    curs_set(0);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(COLOR_REPLY, COLOR_GREEN, -1);
        init_pair(COLOR_QUERY, COLOR_BLUE, -1);
    }

    getmaxyx(stdscr, rows, columns);
    help = newwin(1, columns, 0, 0);
    query = newwin(1, columns, 2, 0);
    result = newwin(rows - 2, columns, 3, 0);
    status = newwin(1, columns, 1, 0);

    mvwprintw(help, 0, 0, HELP_MSG);
    mvwprintw(status, 0, 0, "Status: Running");

    wrefresh(help);
    wrefresh(query);
    wrefresh(result);
    wrefresh(status);

    keypad(query, TRUE);

    struct sigaction action = {0};
    action.sa_handler = handle_resize;
    sigemptyset(&action.sa_mask);
    sigaction(SIGWINCH, &action, NULL);

    for (;;) {

        if (terminal_resized) {
            terminal_resized = 0;
            ioctl(STDIN_FILENO, TIOCGWINSZ, &terminal_size);
            printf("\nTerminal resized: %d rows, %d columns\n", terminal_size.ws_row, terminal_size.ws_col);
            fflush(stdout);
        }

        key = wgetch(query);

        if (start == 0) {
            switch (key) {
                case 'q': // quit
                    goto done;
                    break;
                case 'r': // send request
                    i = 0;
                    start = 1;
                    memset(requestbuf, 0, BUFF_SZ);
                    curs_set(1);
                    werase(query);
                    wmove(query, 0, 0);
                    winsdelln(query, 1);
                    mvwprintw(query, 0, 0, "Request: ");
                    wrefresh(query);
                    break;
                case 'p': // pause/resume
                    signal = (uint64_t)key;
                    write(efd, &signal, sizeof(signal));
                    isPaused = !isPaused;
                    werase(status);
                    mvwprintw(status, 0, 0,
                            "Status: %s", isPaused ? "Paused" : "Running");
                    wrefresh(status);
                    break;
                case 'c': // clear screen
                    werase(result);
                    wrefresh(result);
                    break;
                default:
                    break;
            }
            continue;
        }
        
        if ((key == '\r') || (key == '\n')) {
            curs_set(0);
            requestbuf[i] = '\0';
            signal = 'r';
            write(efd, &signal, sizeof(signal));
            start = 0;
            continue;
        }

        if ((key == KEY_BACKSPACE) || (key == 127) || (key == 8)) {
            if (i > 0) {
                i--;
                requestbuf[i] = '\0';
                wmove(query, 0, 9 + i);
                waddch(query, ' ');
                wmove(query, 0, 9 + i);
                wrefresh(query);
            }
        } else if (key >= 32 && key <= 126) {
            if (i < sizeof(requestbuf) - 1) {
                requestbuf[i++] = (char)key;
                requestbuf[i] = '\0';
                waddch(query, key);
                wrefresh(query);
            }
        }
    }

done:
    signal = (uint64_t)key;
    write(efd, &signal, sizeof(signal));

    delwin(result);
    delwin(query);
    delwin(help);
    delwin(status);
    endwin();

    return NULL;
}
