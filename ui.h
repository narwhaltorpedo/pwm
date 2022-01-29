/*
 * Terminal user interface utilities.
 *
 */

#ifndef PWM_USER_INTERFACE_INCLUDE_GUARD
#define PWM_USER_INTERFACE_INCLUDE_GUARD


/*--------------------------------------------------------------------------------------------------
*
* Turn echo on/off.
*
*-------------------------------------------------------------------------------------------------*/
void TurnEchoOn
(
    bool on                             ///< [IN] true to turn echo on; false otherwise.
);


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
);


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
);


/*--------------------------------------------------------------------------------------------------
*
* Gets an unsigned integer from the standard input.
*
*-------------------------------------------------------------------------------------------------*/
size_t GetUnsignedInt
(
    size_t minValue,                    ///< [IN] Minimum acceptable value.
    size_t maxValue                     ///< [IN] Maximum acceptable value.
);


/*--------------------------------------------------------------------------------------------------
*
* Gets a password from the standard input.
*
*-------------------------------------------------------------------------------------------------*/
void GetPassword
(
    char *pwdPtr,                       ///< [OUT] Password.
    size_t maxPasswordSize              ///< [IN] Maximum password size.
);


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
);


/*--------------------------------------------------------------------------------------------------
*
* Clear the clipboard.
*
*-------------------------------------------------------------------------------------------------*/
void ClearClipboard
(
    void
);


#endif // PWM_USER_INTERFACE_INCLUDE_GUARD
