/*
 * Crypto utilities interface.
 *
 */

#include "pwm.h"
#include "crypto.h"

#include "tomcrypt.h"


/*--------------------------------------------------------------------------------------------------
*
* Encrypt a buffer of data.
*
* @warning
*       This function always uses a zero nonce so do not call this function more than once with the
*       same key.
*
* @return
*       true if successful.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool Encrypt
(
    const uint8_t *keyPtr,              ///< [IN] Key to encrypt with.  Assumed to be KEY_SIZE.
    const uint8_t *noncePtr,            ///< [IN] Nonce.  Assumed to be NONCE_SIZE.
    const uint8_t *ptPtr,               ///< [IN] Plaintext.
    uint8_t *ctPtr,                     ///< [OUT] Ciphertext.
    size_t textSize,                    ///< [IN] Size of both plaintext and ciphertext.
    uint8_t *tagPtr                     ///< [OUT] Tag.  Assumed to be TAG_SIZE.
)
{
    size_t tagLen = TAG_SIZE;

    if (chacha20poly1305_memory(keyPtr, KEY_SIZE,
                                noncePtr, NONCE_SIZE,
                                NULL, 0,
                                ptPtr, textSize,
                                ctPtr,
                                tagPtr, &tagLen,
                                CHACHA20POLY1305_ENCRYPT) != CRYPT_OK)
    {
        return false;
    }

    if (tagLen != TAG_SIZE)
    {
        return false;
    }

    return true;
}


/*--------------------------------------------------------------------------------------------------
*
* Decrypt a buffer of data.
*
* @return
*       true if successful.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool Decrypt
(
    const uint8_t *keyPtr,              ///< [IN] Key to decrypt with.  Assumed to be KEY_SIZE.
    const uint8_t *noncePtr,            ///< [IN] Nonce.  Assumed to be NONCE_SIZE.
    const uint8_t *ctPtr,               ///< [IN] Ciphertext.
    uint8_t *ptPtr,                     ///< [OUT] Plaintext.
    size_t textSize,                    ///< [IN] Size of both plaintext and ciphertext.
    const uint8_t *tagPtr               ///< [IN] Tag.  Assumed to be TAG_SIZE.
)
{
    size_t tagLen = TAG_SIZE;

    return chacha20poly1305_memory(keyPtr, KEY_SIZE,
                                   noncePtr, NONCE_SIZE,
                                   NULL, 0,
                                   ctPtr, textSize,
                                   ptPtr,
                                   (uint8_t*)tagPtr, &tagLen,
                                   CHACHA20POLY1305_DECRYPT) == CRYPT_OK;
}
