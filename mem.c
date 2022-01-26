/*
 * Memory utilities.
 *
 */

#include "pwm.h"
#include "mem.h"


/*--------------------------------------------------------------------------------------------------
*
* Sensitive buffer type.
*
*-------------------------------------------------------------------------------------------------*/
typedef struct
{
    size_t bufSize;
    void* bufPtr;
}
SensitiveBuf_t;


/*--------------------------------------------------------------------------------------------------
*
* Keep an array of sensitive buffers.
*
*-------------------------------------------------------------------------------------------------*/
#define NUM_SENSITIVE_BUFS              (100)
static SensitiveBuf_t SensitiveBufs[NUM_SENSITIVE_BUFS] = {{0, NULL}};


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
)
{
    size_t i = 0;
    for (; i < NUM_SENSITIVE_BUFS; i++)
    {
        if (SensitiveBufs[i].bufPtr != NULL)
        {
            Zerorize(SensitiveBufs[i].bufPtr, SensitiveBufs[i].bufSize);
        }
    }
}


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
)
{
    // Search for an available buffer.
    size_t i = 0;
    for (; i < NUM_SENSITIVE_BUFS; i++)
    {
        if (SensitiveBufs[i].bufPtr == NULL)
        {
            SensitiveBufs[i].bufPtr = malloc(bufSize);
            INTERNAL_ERR_IF(SensitiveBufs[i].bufPtr == NULL, "Could not allocate memory.");
            SensitiveBufs[i].bufSize = bufSize;
            return SensitiveBufs[i].bufPtr;
        }
    }

    INTERNAL_ERR("No more sensitive memory buffers.");
    return NULL; // Not needed but included to avoid compiler warning.
}


/*--------------------------------------------------------------------------------------------------
*
* Release and zerorize a sensitive memory buffer.
*
*-------------------------------------------------------------------------------------------------*/
void ReleaseSensitiveBuf
(
    void* bufPtr                        ///< [IN] Buffer to release.
)
{
    // Check that the buffer is one of ours.
    size_t i = 0;
    for (; i < NUM_SENSITIVE_BUFS; i++)
    {
        if (SensitiveBufs[i].bufPtr == bufPtr)
        {
            Zerorize(SensitiveBufs[i].bufPtr, SensitiveBufs[i].bufSize);
            free(SensitiveBufs[i].bufPtr);
            SensitiveBufs[i].bufPtr = NULL;
            SensitiveBufs[i].bufSize = 0;
            bufPtr = NULL;
            return;
        }
    }

    INTERNAL_ERR("Trying to release a non-sensitive buffer.");
}


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
)
{
    INTERNAL_ERR_IF((buf1Ptr == NULL) || (buf2Ptr == NULL), "Buffer pointers must not be NULL.");

    const uint8_t* b1Ptr = buf1Ptr;
    const uint8_t* b2Ptr = buf2Ptr;
    uint8_t result = 0;

    size_t i = 0;
    for (; i < bufSize; i++)
    {
        result |= b1Ptr[i] ^ b2Ptr[i];
    }

    return (result == 0);
}


/*--------------------------------------------------------------------------------------------------
*
* Zerorize a memory buffer.
*
*-------------------------------------------------------------------------------------------------*/
void Zerorize
(
    volatile void *bufPtr,              ///< [IN] Buffer to zerorize.
    size_t bufSize                      ///< [IN] Buffer size.
)
{
    volatile uint8_t* bPtr = bufPtr;

    INTERNAL_ERR_IF(bufPtr == NULL, "Buffer pointer to zeroize must not be NULL.");

    size_t i = 0;
    for (; i < bufSize; i++)
    {
        bPtr[i] = 0;
    }
}
