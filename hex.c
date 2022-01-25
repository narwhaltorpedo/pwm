/*
 * Utilities for handling HEX strings.
 *
 */

#include "pwm.h"
#include "hex.h"


/*--------------------------------------------------------------------------------------------------
*
* Converts an array of unsigned bytes to hex.
*
* @return
*      Number of bytes of the binPtr array converted.
*
*-------------------------------------------------------------------------------------------------*/
size_t BinToHexStr
(
    const uint8_t*  binPtr,         ///< [IN] Array of unsigned bytes.
    size_t          binSize,        ///< [IN] Array size.
    char*           bufPtr,         ///< [OUT] Buffer to hold the hex string.
    size_t          bufSize         ///< [IN] Buffer size.
)
{
    int i = 0;
    int j = 0;
    while ( (i + 2 < bufSize) && (j < binSize) )
    {
        snprintf(bufPtr + i, 3, "%.2x", binPtr[j]);
        i += 2;
        j++;
    }

    return j;
}
