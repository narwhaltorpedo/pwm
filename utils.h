/*
 * General utilities.
 *
 */

#ifndef PWM_UTILITIES_INCLUDE_GUARD
#define PWM_UTILITIES_INCLUDE_GUARD


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
);


#endif // PWM_UTILITIES_INCLUDE_GUARD
