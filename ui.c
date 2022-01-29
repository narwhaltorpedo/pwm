/*
 * Terminal user interface utilities.
 *
 */

#include <termios.h>
#include <unistd.h>
#include <poll.h>
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include "pwm.h"
#include "ui.h"
#include "password.h"

/*--------------------------------------------------------------------------------------------------
*
* X11 parameters.
*
*-------------------------------------------------------------------------------------------------*/
static Display *DisplayPtr = NULL;
static Atom Clipboard;


/*--------------------------------------------------------------------------------------------------
*
* Send to deny request to X11 clients asking for our clipboard data.
*
*-------------------------------------------------------------------------------------------------*/
static void SendDeny
(
    Display *displayPtr,
    XSelectionRequestEvent *selReqPtr
)
{
    XSelectionEvent selEvent;

    selEvent.type = SelectionNotify;
    selEvent.requestor = selReqPtr->requestor;
    selEvent.selection = selReqPtr->selection;
    selEvent.target = selReqPtr->target;
    selEvent.property = None;
    selEvent.time = selReqPtr->time;

    XSendEvent(displayPtr, selReqPtr->requestor, True, NoEventMask, (XEvent *)&selEvent);
}


/*--------------------------------------------------------------------------------------------------
*
* Send possible target list to requesting client.
*
*-------------------------------------------------------------------------------------------------*/
static void SendTargets
(
    Display *displayPtr,
    XSelectionRequestEvent *selReqPtr,
    Atom utf8
)
{
    Atom targetList[] = {utf8};
    XSelectionEvent selEvent;

    XChangeProperty(displayPtr, selReqPtr->requestor, selReqPtr->property, XA_ATOM, 32,
                    PropModeReplace, (const unsigned char *)targetList, 1);

    selEvent.type = SelectionNotify;
    selEvent.requestor = selReqPtr->requestor;
    selEvent.selection = selReqPtr->selection;
    selEvent.target = selReqPtr->target;
    selEvent.property = selReqPtr->property;
    selEvent.time = selReqPtr->time;

    XSendEvent(displayPtr, selReqPtr->requestor, True, NoEventMask, (XEvent *)&selEvent);
}


/*--------------------------------------------------------------------------------------------------
*
* Send string to requesting client.
*
*-------------------------------------------------------------------------------------------------*/
static void SendUtf8
(
    Display *displayPtr,
    XSelectionRequestEvent *selReqPtr,
    Atom utf8,
    const char *strPtr
)
{
    XSelectionEvent selEvent;

    XChangeProperty(displayPtr, selReqPtr->requestor, selReqPtr->property, utf8, 8, PropModeReplace,
                    (const unsigned char *)strPtr, strlen(strPtr));

    selEvent.type = SelectionNotify;
    selEvent.requestor = selReqPtr->requestor;
    selEvent.selection = selReqPtr->selection;
    selEvent.target = selReqPtr->target;
    selEvent.property = selReqPtr->property;
    selEvent.time = selReqPtr->time;

    XSendEvent(displayPtr, selReqPtr->requestor, True, NoEventMask, (XEvent *)&selEvent);
}


/*--------------------------------------------------------------------------------------------------
*
* Start sharing text with clipboard.  This function will block until there is activity on STDIN.
* Once this function returns the text will no longer be available to the clipboard.
*
*-------------------------------------------------------------------------------------------------*/
static void ShareWithClipboard
(
    const char *textPtr                 ///< [IN] Text to copy.
)
{
    DisplayPtr = XOpenDisplay(NULL);
    INTERNAL_ERR_IF(DisplayPtr == NULL, "Could not open X display.");

    int screen = DefaultScreen(DisplayPtr);
    Window root = RootWindow(DisplayPtr, screen);

    // Create a window to receive messages from clients.
    Window owner = XCreateSimpleWindow(DisplayPtr, root, -10, -10, 1, 1, 0, 0, 0);

    Clipboard = XInternAtom(DisplayPtr, "CLIPBOARD", False);
    Atom utf8 = XInternAtom(DisplayPtr, "UTF8_STRING", False);
    Atom getTargets = XInternAtom(DisplayPtr, "TARGETS", False);

    // Claim ownership of the clipboard.
    XSetSelectionOwner(DisplayPtr, Clipboard, owner, CurrentTime);

    // Handle events.
    int xFd = ConnectionNumber(DisplayPtr);

    struct pollfd fdSet[2] = { {.fd = xFd, .events = POLLOUT},
                               {.fd = STDIN_FILENO, .events = POLLIN} };

    while (1)
    {
        int numReadyFds = poll(fdSet, 2, -1);

        INTERNAL_ERR_IF(numReadyFds == -1, "Poll failed.  %m.");

        if (fdSet[1].revents != 0)
        {
            // Something available on stdin.
            break;
        }

        if (fdSet[0].revents & POLLOUT)
        {
            // X11 events.
            while (XPending(DisplayPtr) > 0)
            {
                char *reqNamePtr = NULL;
                XSelectionRequestEvent *selReqPtr;
                XEvent event;
                XNextEvent(DisplayPtr, &event);

                switch (event.type)
                {
                    case SelectionClear:
                        goto cleanup;

                    case SelectionRequest:
                        selReqPtr = (XSelectionRequestEvent*)&event.xselectionrequest;

                        XFetchName(DisplayPtr, selReqPtr->requestor, &reqNamePtr);

                        if (selReqPtr->target == getTargets)
                        {
                            SendTargets(DisplayPtr, selReqPtr, utf8);
                        }
                        else if ( (selReqPtr->target != utf8) ||
                                  (selReqPtr->property == None) ||
                                  (reqNamePtr == NULL) )
                        {
                            SendDeny(DisplayPtr, selReqPtr);
                        }
                        else
                        {
                            // Only send data to windows with names.
                            SendUtf8(DisplayPtr, selReqPtr, utf8, textPtr);
                        }
                        break;
                }
            }
        }
        else if (fdSet[0].revents != 0)
        {
            goto cleanup;
        }

    }

cleanup:

    ClearClipboard();
}


/*--------------------------------------------------------------------------------------------------
*
* Turn echo on/off.
*
*-------------------------------------------------------------------------------------------------*/
void TurnEchoOn
(
    bool on                             ///< [IN] true to turn echo on; false otherwise.
)
{
    struct termios termAttr;

    INTERNAL_ERR_IF(tcgetattr(STDIN_FILENO, &termAttr) != 0,
                    "Could not get standard in attributes.  %m.");

    if (on)
    {
        termAttr.c_lflag |= ECHO;
    }
    else
    {
        termAttr.c_lflag &= ~ECHO;
    }

    INTERNAL_ERR_IF(tcsetattr(STDIN_FILENO, TCSAFLUSH, &termAttr) != 0,
                    "Could not set standard in attributes.  %m.");
}


/*--------------------------------------------------------------------------------------------------
*
* Gets a line from the standard input.  Reading stops after a EOF or a newline.  The newline
* character is not included in the linePtr.  The linePtr is always NULL terminated.  A maximum of
* bufSize - 1 characters is read from standard input to allow room for the NULL terminator.  If more
* than bufSize - 1 characters is available on the standard input these characters will be flushed
* up to the next newline character and the user will be asked to try again.
*
*-------------------------------------------------------------------------------------------------*/
void GetLine
(
    char* bufPtr,                       ///< [OUT] Buffer to store the line.
    size_t bufSize                      ///< [IN] Buffer size.
)
{
    while (1)
    {
        INTERNAL_ERR_IF(fgets(bufPtr, bufSize, stdin) == NULL,
                        "Could not read standard in.  %m.");

        size_t len = strlen(bufPtr);

        if (bufPtr[len-1] == '\n')
        {
            bufPtr[len-1] = '\0';
            break;
        }
        else
        {
            int c = getchar();

            if (c == '\n')
            {
                // If the character following the line is a newline then that's OK.
                break;
            }

            PRINT("Entry is too long.  Try again:");

            // Flush everything up to the next newline.
            do
            {
                c = getchar();
            }
            while ( (c != '\n') && (c != EOF) );
        }
    }
}


/*--------------------------------------------------------------------------------------------------
*
* Gets a yes/no answer from stdin.
*
* @return
*       true if yes.
*       false if no.
*
*-------------------------------------------------------------------------------------------------*/
bool GetYesNo
(
    bool defaultYes                     ///< [IN] If true then an empty string is considered a "yes"
                                        ///       else an empty string is considered a "no".
)
{
    while (1)
    {
        char answer[4];
        GetLine(answer, sizeof(answer));

        if (strcmp(answer, "") == 0)
        {
            if (defaultYes)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        if ( (strcmp(answer, "y") == 0) ||
             (strcmp(answer, "Y") == 0) ||
             (strcmp(answer, "yes") == 0) ||
             (strcmp(answer, "Yes") == 0) ||
             (strcmp(answer, "YES") == 0) )
        {
            return true;
        }

        if ( (strcmp(answer, "n") == 0) ||
             (strcmp(answer, "N") == 0) ||
             (strcmp(answer, "no") == 0) ||
             (strcmp(answer, "No") == 0) ||
             (strcmp(answer, "NO") == 0) )
        {
            return false;
        }

        PRINT("I don't understand.  Please answer yes or no.");
    }
}


/*--------------------------------------------------------------------------------------------------
*
* Gets an unsigned integer from the standard input.
*
*-------------------------------------------------------------------------------------------------*/
size_t GetUnsignedInt
(
    size_t minValue,                    ///< [IN] Minimum acceptable value.
    size_t maxValue                     ///< [IN] Maximum acceptable value.
)
{
    while (1)
    {
        char line[10];
        GetLine(line, sizeof(line));

        char* endPtr;
        size_t val = strtoul(line, &endPtr, 10);

        if ( (line[0] != '\0') && (*endPtr == '\0') )
        {
            if ( (val >= minValue) && (val <= maxValue) )
            {
                return val;
            }

            PRINT("Value must be between %zu and %zu.", minValue, maxValue);
        }
        else
        {
            PRINT("Please enter a number.");
        }
    }
}


/*--------------------------------------------------------------------------------------------------
*
* Gets a password from the standard input.
*
*-------------------------------------------------------------------------------------------------*/
void GetPassword
(
    char* pwdPtr,                       ///< [OUT] Password.
    size_t maxPasswordSize              ///< [IN] Maximum password size.
)
{
    TurnEchoOn(false);

    while (1)
    {
        GetLine(pwdPtr, maxPasswordSize);

        // Check validity.
        if (IsPasswordValid(pwdPtr))
        {
            break;
        }

        PRINT("Try again:");
    }

    TurnEchoOn(true);
}


/*--------------------------------------------------------------------------------------------------
*
* See if the user wants to share the password with the clipboard.  This function will block until
* there is activity on STDIN.  Once this function returns the text will no longer be available to
* the clipboard.
*
*-------------------------------------------------------------------------------------------------*/
void SharePasswordWithClipboard
(
    const char *pwdPtr                  ///< [IN] Text to copy.
)
{
    PRINT("Do you want the password available in the clipboard [Y/n]?");
    if (GetYesNo(true))
    {
        PRINT("OK hit any key when you are done with the password.");

        ShareWithClipboard(pwdPtr);

        // Flush everything up to the next newline.
        int c;
        do
        {
            c = getchar();
        }
        while ( (c != '\n') && (c != EOF) );
    }
}


/*--------------------------------------------------------------------------------------------------
*
* Clear the clipboard.
*
*-------------------------------------------------------------------------------------------------*/
void ClearClipboard
(
    void
)
{
    if (DisplayPtr != NULL)
    {
        XCloseDisplay(DisplayPtr);
        DisplayPtr = NULL;
    }
}
