/*
 * Memory utilities.
 *
 */

#ifndef PWM_MEMORY_INCLUDE_GUARD
#define PWM_MEMORY_INCLUDE_GUARD


/*--------------------------------------------------------------------------------------------------
*
* Zerorize all sensitive memory buffers.
*
* @return
*       Buffer
*
*-------------------------------------------------------------------------------------------------*/
void ZerorizeSensitiveBufs
(
    void
);


/*--------------------------------------------------------------------------------------------------
*
* Get a memory buffer that can be used to store sensitive memory.  This buffer will be automatically
* zerorized when it is released or if the program shutsdown or crashes.
*
* @return
*       Buffer
*
*-------------------------------------------------------------------------------------------------*/
void *GetSensitiveBuf
(
    size_t bufSize                      ///< [IN] Buffer size.
);


/*--------------------------------------------------------------------------------------------------
*
* Release and zerorize a sensitive memory buffer.
*
*-------------------------------------------------------------------------------------------------*/
void ReleaseSensitiveBuf
(
    void* bufPtr                        ///< [IN] Buffer to release.
);


/*--------------------------------------------------------------------------------------------------
*
* Compare two equal size memory buffers in constant time.
*
* @return
*       true if the buffers are equal.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool IsEqual
(
    const void *buf1Ptr,                ///< [IN] Buffer 1.
    const void *buf2Ptr,                ///< [IN] Buffer 2.
    size_t bufSize                      ///< [IN] Buffer size.
);


/*--------------------------------------------------------------------------------------------------
*
* Zerorize a memory buffer.
*
*-------------------------------------------------------------------------------------------------*/
void Zerorize
(
    volatile void *bufPtr,              ///< [IN] Buffer to zerorize.
    size_t bufSize                      ///< [IN] Buffer size.
);


#endif // PWM_MEMORY_INCLUDE_GUARD
