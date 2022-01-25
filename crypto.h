/*
 * Crypto utilities interface.
 *
 */

#ifndef PWM_CRYPTO_INCLUDE_GUARD
#define PWM_CRYPTO_INCLUDE_GUARD


/*--------------------------------------------------------------------------------------------------
*
* Size definitions.
*
*-------------------------------------------------------------------------------------------------*/
#define KEY_SIZE                        32
#define TAG_SIZE                        16
#define SALT_SIZE                       32
#define NONCE_SIZE                      12


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
);


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
);


#endif // PWM_CRYPTO_INCLUDE_GUARD
