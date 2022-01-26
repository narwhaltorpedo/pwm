/*
 * File access utilities.
 *
 */

#ifndef PWM_FILE_INCLUDE_GUARD
#define PWM_FILE_INCLUDE_GUARD


/*--------------------------------------------------------------------------------------------------
*
* Create a file and open it for writing.
*
* @return
*       An open file descriptor if successful.
*       -1 otherwise.
*
*-------------------------------------------------------------------------------------------------*/
int CreateFile
(
    const char *fileNamePtr             ///< [IN] Path of fle to create.
);


/*--------------------------------------------------------------------------------------------------
*
* Open a file for reading.
*
* @return
*       An open file descriptor if successful.
*       -1 otherwise.
*
*-------------------------------------------------------------------------------------------------*/
int OpenFile
(
    const char *fileNamePtr             ///< [IN] Path of fle to create.
);


/*--------------------------------------------------------------------------------------------------
*
* Writes exactly bufSize bytes to a file.
*
* @return
*      true if successful.
*      false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool WriteBuf
(
    int             fd,                 ///< [IN] Open file descriptor to write to.
    const uint8_t*  bufPtr,             ///< [IN] Buffer to write.
    size_t          bufSize             ///< [IN] Size of buffer.
);


/*--------------------------------------------------------------------------------------------------
*
* Reads bufSize bytes from a file or until the end of file is reached.
*
* @return
*       true if successful.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool ReadBuf
(
    int             fd,                 ///< [IN] Open file descriptor to read from.
    uint8_t*        bufPtr,             ///< [OUT] Buffer to store read data.
    size_t*         bufSizePtr          ///< [IN/OUT] Size of buffer.
);


/*--------------------------------------------------------------------------------------------------
*
* Reads exactly bufSize bytes from a file.
*
* @return
*       true if successful.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool ReadExactBuf
(
    int             fd,                 ///< [IN] Open file descriptor to read from.
    uint8_t*        bufPtr,             ///< [OUT] Buffer to store read data.
    size_t          bufSize             ///< [IN] Size of buffer.
);


/*--------------------------------------------------------------------------------------------------
*
* Checks if the file exists.
*
* @return
*       true if the file exists.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool DoesFileExist
(
    const char *pathPtr                 ///< [IN] Path to check.
);


/*--------------------------------------------------------------------------------------------------
*
* Deletes an entire directory.
*
* @return
*       true if successful.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool DeleteDir
(
    const char *pathPtr                 ///< [IN] Path to directory.
);


#endif // PWM_FILE_INCLUDE_GUARD
