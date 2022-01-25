/*
 * Utilities for printing messages to the screen.
 *
 */

#ifndef PWM_PRINT_INCLUDE_GUARD
#define PWM_PRINT_INCLUDE_GUARD


/*--------------------------------------------------------------------------------------------------
*
* Basename of __FILE__
*
*-------------------------------------------------------------------------------------------------*/
#ifndef __FILENAME__
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif


/*--------------------------------------------------------------------------------------------------
*
* Print debug message.
*
*-------------------------------------------------------------------------------------------------*/
#ifdef TEST
#define DEBUG(formatStr, ...)   __PrintErr(__FILENAME__, __LINE__, formatStr, ##__VA_ARGS__)
#else
#define DEBUG(formatStr, ...)
#endif


/*--------------------------------------------------------------------------------------------------
*
* Print debug message if the condition is true.
*
*-------------------------------------------------------------------------------------------------*/
#define DEBUG_IF(condition, formatStr, ...) \
    do \
    { \
        if (condition) \
        { \
            DEBUG(formatStr, ##__VA_ARGS__); \
        } \
    } while (0)


/*--------------------------------------------------------------------------------------------------
*
* Print the error message and exits.
*
*-------------------------------------------------------------------------------------------------*/
#define HALT(formatStr, ...) \
    do \
    { \
        fprintf(stderr, formatStr, ##__VA_ARGS__); \
        fprintf(stderr, "\n"); \
        exit(EXIT_FAILURE); \
    } while (0)


/*--------------------------------------------------------------------------------------------------
*
* Print an error message and exit if the condition is true.
*
*-------------------------------------------------------------------------------------------------*/
#define HALT_IF(condition, formatStr, ...) \
    do \
    { \
        if (condition) \
        { \
            HALT(formatStr, ##__VA_ARGS__); \
        } \
    } while (0)


/*--------------------------------------------------------------------------------------------------
*
* Print a standard error message, debug message and exit.
*
*-------------------------------------------------------------------------------------------------*/
#define INTERNAL_ERR(formatStr, ...) \
    do \
    { \
        fprintf(stderr, "Internal error\n"); \
        DEBUG(formatStr, ##__VA_ARGS__); \
        exit(EXIT_FAILURE); \
    } while (0)


/*--------------------------------------------------------------------------------------------------
*
* Print a standard error message, debug message and exit if the condition is true.
*
*-------------------------------------------------------------------------------------------------*/
#define INTERNAL_ERR_IF(condition, formatStr, ...) \
    do \
    { \
        if (condition) \
        { \
            INTERNAL_ERR(formatStr, ##__VA_ARGS__); \
        } \
    } while (0)


/*--------------------------------------------------------------------------------------------------
*
* Print a standard error message, debug message and exit.
*
*-------------------------------------------------------------------------------------------------*/
#define CORRUPT(formatStr, ...) \
    do \
    { \
        fprintf(stderr, "Data corrupted\n"); \
        DEBUG(formatStr, ##__VA_ARGS__); \
        exit(EXIT_FAILURE); \
    } while (0)


/*--------------------------------------------------------------------------------------------------
*
* Print a standard error message, debug message and exit if the condition is true.
*
*-------------------------------------------------------------------------------------------------*/
#define CORRUPT_IF(condition, formatStr, ...) \
    do \
    { \
        if (condition) \
        { \
            CORRUPT(formatStr, ##__VA_ARGS__); \
        } \
    } while (0)


/*--------------------------------------------------------------------------------------------------
*
* Print a message.
*
*-------------------------------------------------------------------------------------------------*/
#define PRINT(formatString, ...) \
    do \
    { \
        printf(formatString, ##__VA_ARGS__); \
        printf("\n"); \
    } while (0)


/*--------------------------------------------------------------------------------------------------
*
* Prints the line number.
*
*-------------------------------------------------------------------------------------------------*/
#define PRINT_LINE_NUM()            printf("%d\n", __LINE__)


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
);


/*--------------------------------------------------------------------------------------------------
*
* Prints an array of bytes as a hex string.
*
*-------------------------------------------------------------------------------------------------*/
void PrintHexStr
(
    const uint8_t*  bufPtr,         ///< [IN] Array.
    size_t          bufSize         ///< [IN] Array size.
);


#endif // PWM_PRINT_INCLUDE_GUARD
