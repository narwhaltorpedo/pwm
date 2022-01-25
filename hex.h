/*
 * Utilities for handling HEX strings.
 *
 */

#ifndef PWM_HEXIDECIMAL_INCLUDE_GUARD
#define PWM_HEXIDECIMAL_INCLUDE_GUARD


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
);


#endif // PWM_HEXIDECIMAL_INCLUDE_GUARD
