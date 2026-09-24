#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h> 
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>

#include <ncurses.h>

#include "cli.h"
#include "dns.h"
// #include "dns.h"

#define BUFF_SZ 1024
#define MSG_SZ 2048
#define COLOR_REPLY 1
#define COLOR_QUERY 2
#define COLOR_SELECT 3
#define COLOR_HELP 4

#define HELP_MSG "Press 'q' to quit, 'r' to send request, 'p' to pause/resume, 'c' to clear screen"

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct Stat {
    int q;
    int r;
    int ru;
};

struct Node {
    command cmd;
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
static struct Node node = { .cmd = NULL };

uint8_t requestbuf[BUFF_SZ] = {0};

#define ITEMS_SZ 64

/* static */

struct Item {
    int pos;
    uint8_t *rawPacket;
    size_t len;
    struct Item *next;
    struct Item *prev;
};

enum ItemPos {
    deselect,
    next,
    prev
};

static struct Item *head;
static volatile int height;
static volatile int width;
static bool isPaused = false;
static bool isRequestMode = false;
static uint64_t control = 0;
static struct Item *current = NULL;
static uint16_t i = 0;

static void
handle_resize(int signal)
{
    terminal_resized = 1;
}

static void initItem(struct Item **item);
static void deinitItem(struct Item **item);
static void addItem(uint8_t *rawPacket, size_t len, int pos);
static void debugItems();
static void selectItem(struct Item **current, enum ItemPos p);
static void cmdPause();
static void cmdResume();
static void cmdClrScr();
static void cmdRequestMode();
static void cmdSendRequest();
static int requestMode(int key);

/* static end */
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
printToWindow(const char *msg, int lines,
    uint8_t *rawPacket, size_t len)
{
    int i, n = 0;
    wmove(result, 0, 0);
    winsdelln(result, lines);
    n = mvwprintw(result, 0, 0, "%s", msg);
    wrefresh(result);
    addItem(rawPacket, len, lines);
    debugItems();
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
    uint16_t buflen = 0;
    int key = 0;
    struct winsize terminal_size;
    int rows = 0;
    int columns = 0;
    int curr_line = 0;

    initItem(&head);

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
    help =         newwin(1, columns / 2, 0, 0);
    status =       newwin(1, columns / 2, 1, 0);
    query =        newwin(1, columns / 2, 2, 0);

    result =       newwin(rows - 7, columns / 2, 4, 0);
    statusBottom = newwin(2, columns / 2, rows - 2, 0);

    messagebox =   newwin(rows, columns / 2, 0, columns / 2);
    
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

    // updateBottomStatus(10, 10, 10);

    for (;;) {

        if (terminal_resized) {
            terminal_resized = 0;
            ioctl(STDIN_FILENO, TIOCGWINSZ, &terminal_size);
            printf("\nTerminal resized: %d rows, %d columns\n", terminal_size.ws_row, terminal_size.ws_col);
            fflush(stdout);
        }

        key = wgetch(query);

        if (isRequestMode) {
            if (requestMode(key) < 0) {
                control = (uint64_t)key;
                write(efd, &control, sizeof(control));
            }
            continue;
        }

        switch (key) {
            case 'a':
            case 'p': // pause/resume
            case 'c': // clear screen
            case 'r': // enter request mode
            case KEY_DOWN:
            case KEY_UP:
                control = (uint64_t)key;
                write(efd, &control, sizeof(control));
                break;
            case 'q': // quit
                goto done;
                break;
            default:
                break;
        }

    }

done:
    control = (uint64_t)key;
    write(efd, &control, sizeof(control));

    delwin(result);
    delwin(result_frame);
    delwin(query);
    delwin(help);
    delwin(status);
    delwin(messagebox);
    endwin();
    deinitItem(&head);
    pthread_mutex_destroy(&lock);

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

int
executeCommand(int key, CommandCallbacks *cb)
{
    int rv = 0;
    switch (key) {
        case 'p':
            isPaused ? cmdResume() : cmdPause();
            if (cb->pause != NULL) {
                cb->pause();
            }
            break;
        case 'c':
            cmdClrScr();
            if (cb->clrscr != NULL) {
                cb->clrscr();
            }
            break;
        case 'r':
            cmdRequestMode();
            break;
        case '\n':
        case '\r':
            cmdSendRequest();
            if (cb->sendreq != NULL) {
                cb->sendreq();
            }
            break;
        case 'q':
            rv = -1;
            break;
        case KEY_DOWN:
            if (isPaused) {
                selectItem(&current, next);
            }
            break;
        case KEY_UP:
            if (isPaused) {
                selectItem(&current, prev);
            }
            break;
        default:
            break;
    }

    return rv;
}

/* static definitions */
static int
requestMode(int key)
{
    int rv = 0;
    if ((key == KEY_BACKSPACE) || (key == 127) || (key == 8)) {
        if (i > 0) {
            i--;
            requestbuf[i] = '\0';
            wmove(query, 0, 9 + i);
            waddch(query, ' ');
            wmove(query, 0, 9 + i);
            wrefresh(query);
        }
        goto out;
    }
    
    if (key >= 32 && key <= 126) {
        if (i < sizeof(requestbuf) - 1) {
            requestbuf[i++] = (char)key;
            requestbuf[i] = '\0';
            waddch(query, key);
            wrefresh(query);
        }
        goto out;
    }

    rv = -1;

out:
    return rv;
}

static void
cmdSendRequest()
{
    curs_set(0);
    requestbuf[i] = '\0';
    isRequestMode = false;
    werase(query);
    wrefresh(query);
}

static void
cmdRequestMode()
{
    i = 0;
    isRequestMode = true;
    memset(requestbuf, 0, BUFF_SZ);
    curs_set(1);
    werase(query);
    wmove(query, 0, 0);
    winsdelln(query, 1);
    mvwprintw(query, 0, 0, "Request: ");
    wrefresh(query);
}

static void
cmdClrScr()
{
    werase(result);
    wrefresh(result);
    werase(messagebox);
    wrefresh(messagebox);
    deinitItem(&head);
    initItem(&head);
    current = NULL;
}

static void
cmdPause()
{
    isPaused = true;
    selectItem(&current, next);
    werase(status);
    mvwprintw(status, 0, 0,
            "Status: %s", "Paused");
    wrefresh(status);
}

static void
cmdResume()
{
    isPaused = false;
    selectItem(&current, deselect);
    werase(status);
    mvwprintw(status, 0, 0,
            "Status: %s", "Running");
    wrefresh(status);
}

static void
initItem(struct Item **item)
{
    *item = malloc(sizeof(struct Item));
    if (*item == NULL) {
        perror("memory error");
        goto out;
    }
    (*item)->pos = -1;
    (*item)->next = NULL;
    (*item)->prev = NULL;

out:
    return;
}

static void
deinitItem(struct Item **item)
{
    struct Item *tmp = NULL;
    while (((*item)) != NULL) {
        tmp = (*item)->next;
        free(*item);
        *item = tmp;
    }
}

static void
addItem(uint8_t *rawPacket, size_t len, int pos)
{
    struct Item *tmp = NULL;
    struct Item *prev = NULL;
    if (head == NULL) {
        goto out;
    }
    if (head->pos == -1) {
        head->pos = 0;
        head->rawPacket = rawPacket;
        head->len = len;
    } else {
        tmp = malloc(sizeof(struct Item));
        tmp->pos = 0;
        tmp->rawPacket = rawPacket;
        tmp->len = len;
        tmp->next = head;
        head = tmp;
        head->prev = NULL;
        head->next->prev = head;
        prev = head;

        tmp = head->next;
        while (tmp != NULL) {
            tmp->pos += pos;

            /* free all next items */
            if (tmp->pos > height) {
                deinitItem(&tmp);
                tmp = NULL;
                prev->next = NULL;
                break;
            }

            prev = tmp;
            tmp = tmp->next;
        }
    }

out:
    return;
}

static void
debugItems()
{
    struct Item *tmp = head;
    wclear(messagebox);
    while(tmp != NULL) {
        printToMessageBox("item: %p, pos: %d\n", tmp, tmp->pos);
        tmp = tmp->next;
    }
}

static void
selectItem(struct Item **current, enum ItemPos p)
{
    if ((*current) != NULL && p == deselect) {
        mvwchgat(result, (*current)->pos, 0, width, 0, 0, NULL);
        *current = NULL;
        wclear(messagebox);
        goto out;
    }

    if (*current == NULL) {
        *current = head;
    } else if (((*current)->next != NULL) && (p == next)) {
        mvwchgat(result, (*current)->pos, 0, width, 0, 0, NULL);
        *current = (*current)->next;
    } else if (((*current)->prev != NULL) && (p == prev)) {
        mvwchgat(result, (*current)->pos, 0, width, 0, 0, NULL);
        *current = (*current)->prev;
    }
    wclear(messagebox);
    mvwchgat(result, (*current)->pos, 0, width, 0, COLOR_SELECT, NULL);
    debug_dump((*current)->rawPacket, (*current)->len, printToMessageBox);

out:
    wrefresh(result);
    wrefresh(messagebox);
}
