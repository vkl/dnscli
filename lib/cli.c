#include <stdio.h>
#include <stdint.h>
#include <pthread.h> 
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>

#include <ncurses.h>

#include "cli.h"
// #include "dns.h"

#define BUFF_SZ 1024
#define MSG_SZ 2048
#define COLOR_REPLY 1
#define COLOR_QUERY 2
#define COLOR_SELECT 3
#define COLOR_HELP 4

#define HELP_MSG "Press 'q' to quit, 'r' to send request, 'p' to pause/resume, 'c' to clear screen"

struct Stat {
    int q;
    int r;
    int ru;
};

extern int efd;
volatile sig_atomic_t terminal_resized = 0;
static WINDOW *result;
static WINDOW *result_frame;
static WINDOW *query;
static WINDOW *help;
static WINDOW *status;
static WINDOW *messagebox;
static WINDOW *statusBottom;

static struct Stat stat = { .r = 0, .q = 0, .ru = 0 };

uint8_t requestbuf[BUFF_SZ] = {0};

static void
handle_resize(int signal)
{
    terminal_resized = 1;
}

int
printToMessageBox(const char *format, ...)
{
    va_list args;
    int n;

    if (messagebox == NULL || format == NULL) {
        return 0;
    }

    va_start(args, format);
    n = vw_printw(messagebox, format, args);
    va_end(args);

    wrefresh(messagebox);

    return n;
}

int
printToWindow(const char *msg)
{
    int n = 0;
    // int lines = 0;
    // const char *nline = NULL;
    // nline = strchr(msg, '\n');
    // while (nline != NULL) {
    //     lines++;
    //     nline = strchr(nline + 1, '\n');
    // }
    n = waddstr(result, msg);
    wrefresh(result);

    return n;
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
    int key = 0;
    struct winsize terminal_size;
    int rows = 0;
    int columns = 0;
    bool isPaused = false;
    int curr_line = 0;
    int width, height, ypos = 0;

    initscr();
    cbreak();
    noecho();
    curs_set(0);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(COLOR_REPLY, COLOR_GREEN, -1);
        init_pair(COLOR_QUERY, COLOR_BLUE, -1);
        init_pair(COLOR_SELECT, COLOR_BLACK, COLOR_WHITE);
        init_pair(COLOR_HELP, COLOR_WHITE, COLOR_BLUE);
    }

    getmaxyx(stdscr, rows, columns);
    help = newwin(1, columns / 2, 0, 0);
    query = newwin(1, columns / 2, 2, 0);
    status = newwin(1, columns / 2, 1, 0);
    result = newwin(rows - 6, columns / 2, 4, 0);
    messagebox = newwin(rows, columns / 2, 0, columns / 2);
    statusBottom = newwin(2, columns / 2, rows - 2, 0);

    width = getmaxx(result);
    height = getmaxy(result);

    keypad(query, TRUE);
    keypad(result, TRUE);
    scrollok(messagebox, TRUE);
    scrollok(result, TRUE);

    waddstr(help, HELP_MSG);
    mvwprintw(status, 0, 0, "Status: Running");

    wrefresh(help);
    wrefresh(query);
    wrefresh(result);
    wrefresh(status);
    wrefresh(messagebox);
    wrefresh(statusBottom);

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
            printToMessageBox("result: %d %d, press %02x\n", height, width, key);
            switch (key) {
                case 'q': // quit
                    goto done;
                    break;
                case KEY_DOWN:
                    mvwchgat(result, ypos, 0, width, 0, 0, NULL);
                    ypos++;
                    if (ypos >= (height - 1)) ypos = height - 1;
                    mvwchgat(result, ypos, 0, width, 0, COLOR_SELECT, NULL);
                    wrefresh(result);
                    break;
                case KEY_UP:
                    mvwchgat(result, ypos, 0, width, 0, 0, NULL);
                    ypos--;
                    if (ypos <= 0) ypos = 0;
                    mvwchgat(result, ypos, 0, width, 0, COLOR_SELECT, NULL);
                    wrefresh(result);
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
    delwin(result_frame);
    delwin(query);
    delwin(help);
    delwin(status);
    delwin(messagebox);
    endwin();

    return NULL;
}

void
updateBottomStatus(int r, int q, int ru)
{
    stat.q += q;
    stat.r += r;
    stat.ru += ru;
    mvwprintw(statusBottom, 0, 0, "R: %d Q: %d RU: %d",
            stat.r, stat.q, stat.ru);
    wrefresh(statusBottom);
}
