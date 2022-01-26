/*
 * General utilities.
 *
 */


#include "pwm.h"
#include "utils.h"


/*--------------------------------------------------------------------------------------------------
*
* Checks if a string contains only printable characters.
*
* @return
*       true if successful.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool IsPrintable
(
    const char *strPtr,                 ///< [IN] String to check.
    size_t *lenPtr                      ///< [OUT] String length.  NULL if not needed.
)
{
    size_t len = strlen(strPtr);

    if (lenPtr != NULL)
    {
        *lenPtr = len;
    }

    size_t i = 0;
    for (; i < len; i++)
    {
        if (!isprint(strPtr[i]))
        {
            return false;
        }
    }

    return true;
}
