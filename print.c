/*
 * Utilities for printing messages to the screen.
 *
 */

#include "pwm.h"
#include "print.h"


/*--------------------------------------------------------------------------------------------------
*
* Maximum error message size.
*
*-------------------------------------------------------------------------------------------------*/
#define MAX_MSG_SIZE                    100


/*--------------------------------------------------------------------------------------------------
*
* Print an error message.
*
*-------------------------------------------------------------------------------------------------*/
void __PrintErr
(
    const char *filenamePtr,    ///< [IN] Source code file.
    unsigned int lineNumber,    ///< [IN] Source code file line number.
    const char *formatPtr,      ///< [IN] Message format string.
    ...
)
{
    // Save the current errno because some of the system calls below may change errno.
    int savedErrno = errno;

    // Get the user message.
    char userMsg[MAX_MSG_SIZE] = "";

    va_list varParams;
    va_start(varParams, formatPtr);

    errno = savedErrno;

    // Don't need to check the return value because if there is an error we can't do anything about
    // it.  If there was a truncation then that'll just show up in the logs.
    vsnprintf(userMsg, sizeof(userMsg), formatPtr, varParams);

    va_end(varParams);

    // Print debug message.
    fprintf(stderr, "ERROR: %s %d | %s\n", filenamePtr, lineNumber, userMsg);
}


/*--------------------------------------------------------------------------------------------------
*
* Prints an array of bytes as a hex string.
*
*-------------------------------------------------------------------------------------------------*/
void PrintHexStr
(
    const uint8_t*  bufPtr,         ///< [IN] Array.
    size_t          bufSize         ///< [IN] Array size.
)
{
    size_t i;
    for (i = 0; i < bufSize; i++)
    {
        printf("%.2x", bufPtr[i]);
    }

    printf("\n");
}
