/*
 * File access utilities.
 *
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <fts.h>

#include "pwm.h"
#include "file.h"


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
)
{
    int fd;
    do
    {
        fd = creat(fileNamePtr, S_IRUSR | S_IWUSR);
    } while ( (fd == -1) && (errno == EINTR) );

    DEBUG_IF(fd == -1, "Could not create file %s.  %m.", fileNamePtr);

    return fd;
}


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
)
{
    int fd;
    do
    {
        fd = open(fileNamePtr, O_RDONLY);
    } while ( (fd == -1) && (errno == EINTR) );

    DEBUG_IF(fd == -1, "Could not open file %s.  %m.", fileNamePtr);

    return fd;
}


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
)
{
    const uint8_t* currentPtr = bufPtr;
    size_t numBytes = 0;

    while (bufSize - numBytes > 0)
    {
        ssize_t c;
        do
        {
            c = write(fd, currentPtr, bufSize - numBytes);
        } while ( (c == -1) && (errno == EINTR) );

        if (c == -1)
        {
            DEBUG("Could not write to file.  %m.");
            return false;
        }

        numBytes += c;
        currentPtr += c;
    }

    // Flush the write to disk.
    if (fsync(fd) != 0)
    {
        DEBUG("Could not flush to disk.  %m.");
        return false;
    }

    return true;
}


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
)
{
    uint8_t* currentPtr = bufPtr;
    size_t numBytes = 0;

    while (*bufSizePtr >= numBytes)
    {
        ssize_t c;
        do
        {
            c = read(fd, currentPtr, *bufSizePtr - numBytes);
        } while ( (c == -1) && (errno == EINTR) );

        if (c == -1)
        {
            DEBUG("Could not read to file.  %m.");
            return false;
        }

        if (c == 0)
        {
            // Reached end of file.
            break;
        }

        numBytes += c;
        currentPtr += c;
    }

    *bufSizePtr = numBytes;
    return true;
}


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
)
{
    size_t bytesRead = bufSize;

    if (!ReadBuf(fd, bufPtr, &bytesRead) || (bytesRead != bufSize))
    {
        return false;
    }

    return true;
}


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
)
{
    struct stat statBuf;

    if (stat(pathPtr, &statBuf) == 0)
    {
        return true;
    }

    INTERNAL_ERR_IF((errno != ENOENT) && (errno != ENOTDIR), "Could not stat %s.  %m.", pathPtr);

    return false;
}


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
)
{
    struct stat sourceStat;

    if (lstat(pathPtr, &sourceStat) == -1)
    {
        if (errno == ENOENT)
        {
            return true;
        }
        else
        {
            DEBUG("Could not stat '%s'.  %m.", pathPtr);
            return false;
        }
    }
    else if ( (S_ISLNK(sourceStat.st_mode)) || (S_ISREG(sourceStat.st_mode)) )
    {
        if (unlink(pathPtr) == -1)
        {
            DEBUG("Could not unlink '%s'.  %m.", pathPtr);
            return false;
        }

        return true;
    }

    // Open the directory tree to search.
    char* pathArrayPtr[] = {(char*)pathPtr, NULL};

    errno = 0;
    FTS* ftsPtr = fts_open(pathArrayPtr, FTS_PHYSICAL | FTS_NOSTAT, NULL);

    if (ftsPtr == NULL)
    {
        DEBUG("Could not open dir iterator.  %m.");
        return false;
    }

    // Step through the directory tree.
    FTSENT* entPtr;
    while ((entPtr = fts_read(ftsPtr)) != NULL)
    {
        if ( (entPtr->fts_info != FTS_D) && (remove(entPtr->fts_accpath) != 0) )
        {
            DEBUG("Could not remove '%s'.  %m.", entPtr->fts_accpath);
            fts_close(ftsPtr);
            return false;
        }
    }

    int lastErrno = errno;
    fts_close(ftsPtr);

    if (lastErrno != 0)
    {
        DEBUG("Could not find directory '%s'.  %m.", pathPtr);
        return false;
    }

    return true;
}
