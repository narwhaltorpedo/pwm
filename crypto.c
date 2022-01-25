/*
 * Crypto utilities interface.
 *
 */

#include <sys/random.h>

#include "pwm.h"
#include "crypto.h"

#include "argon2.h"
#include "tomcrypt.h"
#include "hex.h"


/*--------------------------------------------------------------------------------------------------
*
* Argon2 parameters.
*
*-------------------------------------------------------------------------------------------------*/
#define MEM_COST                8192        ///< kibibytes.
#define TIME_COST               100         ///< Rounds
#define NUM_THREADS             4


/*--------------------------------------------------------------------------------------------------
*
* Get a buffer of random numbers.
*
*-------------------------------------------------------------------------------------------------*/
void GetRandom
(
    uint8_t *bufPtr,                    ///< [OUT] Buffer.
    size_t bufSize                      ///< [IN] Buffer size.
)
{
    INTERNAL_ERR_IF(getrandom(bufPtr, bufSize, GRND_NONBLOCK) != bufSize,
                    "Could get random numbers.");
}


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


/*--------------------------------------------------------------------------------------------------
*
* Derive a key.
*
* @return
*       true if successful.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool DeriveKey
(
    const char *secretPtr,              ///< [IN] Secret to use.
    const uint8_t *saltPtr,             ///< [IN] Random salt.
    size_t saltSize,                    ///< [IN] Size of the salt.
    const char *labelPtr,               ///< [IN] Label.
    uint8_t *keyPtr,                    ///< [OUT] Key.
    size_t keySize                      ///< [IN] Size of key.
)
{
    argon2_context context;
    context.out = keyPtr;
    context.outlen = keySize;
    context.pwd = (uint8_t *)secretPtr;
    context.pwdlen = (uint32_t)strlen(secretPtr);
    context.salt = (uint8_t *)saltPtr;
    context.saltlen = (uint32_t)saltSize;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = (uint8_t *)labelPtr;
    context.adlen = (uint32_t)strlen(labelPtr);
    context.t_cost = TIME_COST;
    context.m_cost = MEM_COST;
    context.lanes = NUM_THREADS;
    context.threads = NUM_THREADS;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;
    context.version = ARGON2_VERSION_NUMBER;

    int ret = argon2_ctx(&context, Argon2_id);

    if (ret != ARGON2_OK)
    {
        DEBUG("Argon2 failed %d", ret);
        return false;
    }

    return true;
}


/*--------------------------------------------------------------------------------------------------
*
* Derive a name (string) from a secret string, salt and a label.  The name will always be NULL
* terminated and will be as close to the maximum name size as possible.
*
* @return
*       true if successful.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool DeriveName
(
    const char *secretPtr,              ///< [IN] Secret to use.
    const uint8_t *saltPtr,             ///< [IN] Random salt.
    size_t saltSize,                    ///< [IN] Size of the salt.
    const char *labelPtr,               ///< [IN] Label.
    char *namePtr,                      ///< [OUT] Derived name.
    size_t maxNameSize                  ///< [IN] Maximum name size.
)
{
    size_t binNameSize = (maxNameSize / 2) - 1;
    uint8_t *binNamePtr = malloc(binNameSize);

    if (binNamePtr == NULL)
    {
        return false;
    }

    if (!DeriveKey(secretPtr, saltPtr, saltSize, labelPtr, binNamePtr, binNameSize))
    {
        return false;
    }

    if (BinToHexStr(binNamePtr, binNameSize, namePtr, maxNameSize) != binNameSize)
    {
        return false;
    }

    return true;
}
