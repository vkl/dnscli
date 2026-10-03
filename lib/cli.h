#ifndef _CLI_H
#define _CLI_H

#include <curses.h>
#include <stdint.h>

enum Event {
    None,
    Pause,
    Resume
};

typedef void (*command) ();
typedef void (*callback)(void);

typedef struct {
    callback pause;
    callback clrscr;
    callback sendreq;
} CommandCallbacks;

void *interactive(void *arg);
int printToWindow(const char *msg, int lines, uint8_t *rawPacket, size_t len);
int printToMessageBox(const char *format, ...);
void updateBottomStatus(int r, int q, int ru);
int executeCommand(int key, CommandCallbacks *cb);

#endif

