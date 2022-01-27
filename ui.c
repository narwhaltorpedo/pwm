/*
 * Terminal user interface utilities.
 *
 */

#include <termios.h>
#include <unistd.h>
#include "pwm.h"
#include "ui.h"
#include "password.h"


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
