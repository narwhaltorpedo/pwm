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


/*--------------------------------------------------------------------------------------------------
*
* Derive a key from a secret string and a salt.
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
);


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
);


#endif // PWM_CRYPTO_INCLUDE_GUARD
