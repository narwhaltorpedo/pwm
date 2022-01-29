/*
 * Password manager command line utility.
 *
 * @section Introduction
 *
 * This utility assumes a single user.  The user can create items that contain a username, password
 * and other info.  Each item must have a unique name.  Each item is stored as a file under the
 * storage directory.  The item filenames are derived as described below.
 *
 * @section System File
 *
 * In addition to the item files a system file is also stored under the storage directory.  The
 * system file is created when the system is first initialized.  Unlike the item files the system
 * file is created with a fix name.  The system contains the following information:
 * __________________________________________________________
 * | version | fileSalt | nameSalt | salt | tag | ciphertext |
 * ----------------------------------------------------------
 *
 * The ciphertext is the encrypted configuration data.  The tag is the authentication for the
 * ciphertext.  The salt is used to derive the encryption key to encrypt the configuration data as
 * follows:
 *      ConfigEncryptionKey = KDF(masterPassword, salt, dataEncryptionLabel)
 *
 * The nameSalt is used to derive item filenames:
 *      itemFileName = KDF(masterPassword, nameSalt, itemName | filenameLabel)
 *
 * The fileSalt is used to derive an item name encryption key:
 *      ItemNameEncryptionKey = KDF(masterPassword, fileSalt, filenameEncryptionLabel)
 *
 * The labels in the KDF functions are fixed strings.
 *
 * @section Item Files
 *
 * The item files contain the following information:
 * ________________________________________________________________________________
 * | version |  nameNonce | nameTag | nameCiphertext | salt | tag | itemCiphertext |
 * --------------------------------------------------------------------------------
 *
 * The itemCiphertext is the encrypted username, password and other info for the item.  The tag is
 * the authentication tag for the itemCiphertext.  The salt is used to derive the encryption key
 * for the itemCiphertext as follows:
 *      ItemEncryptionKey = KDF(masterPassword, salt, dataEncryptionLabel)
 *
 * The nameCiphertext is the encrypted item name.  The nameTag is the authentication tag for the
 * nameCiphertext.  The nameNonce is the nonce when encrypting item name as follows:
 *      (nameCiphertext, nameTag) = Encrypt(ItemNameEncryptionKey, nameNonce)
 *
 * @section Rationale
 *
 * The item files use a derived name to hide the item names.  This works well when creating and
 * getting an item as the user provides the item name.  However, this does not work when listing
 * the items in the system because the user does not provide the item name.  To make listing work
 * the item name is encrypted under an ItemNameEncryptionKey and stored in the item file.  This may
 * not be ideal and other options were explored such as using deterministic encryption for the file
 * names but was rejected due to limitations in filename lengths.
 *
 * When the items are listed they are first decrypted into an array of item names and then sorted
 * before they are displayed.  This hides the mapping between the item names and the file mappings.
 *
 * In the KDF functions a fixed label is included to distinguish the use of the KDF.
 *
 * Argon2id is used as the KDF because it can be tuned for time and memory requirements to slow down
 * master password cracking.
 *
 * All memory in the process is locked which prevents swaps to disk.  This is to prevent secret data
 * from accidentally being stored to disk.  However, there is a limit (RLIMIT_MEMLOCK) to how much
 * memory a non-root process can lock which was actually found to be under the recommended memory
 * setting for Argon2.  The current solution is just to set the Argon2 memory as high as possible
 * and then tune the time value to be reasonably tolerable.  But some of these other solutions could
 * be explored in the future:
 *      - Run the program as a setuid program that would start up as root, raise the RLIMIT_MEMLOCK
 *        value then drop privileges.
 *      - Lock only certain regions of memory that are likely to contain secrets.
 *
 * All fields in the system file as well as the item files are fixed sized.  For the itemCiphertext
 * to be a fixed length the variable length data (username, password, other info) is padded with
 * zeros where necessary.  Padding with zeros is unambiguous because the plaintext is treated as a
 * NULL-terminated string.
 *
 * Chacha20poly1305 is used for data and item name encryption.  The nonce value is chacha20poly1305
 * is only 96 bits which can be risky to generate randomly.  This is not a problem for data
 * encryption because a new key is used for each invocation.  In fact for data encryption we use a
 * fixed nonce for this reason.  For item name encryption we generate the nonce randomly for each
 * invocation so maybe in the future Xchacha20poly1305 would be a better choice.
 *
 * To help with zeroization of sensitive data we create a sensitive memory allocator that
 * automatically zerorizes the memory before freeing it.  To make this more robust we create a
 * termination action and a signal handler that zerorizes and frees all sensitive buffers in case of
 * a process termination.
 */

#define _GNU_SOURCE

#include <termios.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/stat.h>
#include <fts.h>

#include "pwm.h"
#include "ui.h"
#include "mem.h"
#include "crypto.h"
#include "file.h"
#include "password.h"


/*--------------------------------------------------------------------------------------------------
*
* Storage location relative to the home directory.
*
*-------------------------------------------------------------------------------------------------*/
#define STORAGE_DIR                     "PwmStore"


/*--------------------------------------------------------------------------------------------------
*
* System file name.
*
*-------------------------------------------------------------------------------------------------*/
#define SYSTEM_FILE_NAME                "system"


/*--------------------------------------------------------------------------------------------------
*
* Size definitions.
*
*-------------------------------------------------------------------------------------------------*/
#define MAX_ITEM_NAME_SIZE              100
#define MAX_USERNAME_SIZE               100
#define MAX_OTHER_INFO_SIZE             300
#define ITEM_SIZE                       (MAX_ITEM_NAME_SIZE + MAX_USERNAME_SIZE + MAX_PASSWORD_SIZE + MAX_OTHER_INFO_SIZE)
#define FILENAME_SIZE                   65


/*--------------------------------------------------------------------------------------------------
*
* Known paths.
*
*-------------------------------------------------------------------------------------------------*/
static char StoragePath[PATH_MAX];
static char SystemPath[PATH_MAX];
static char TempPath[PATH_MAX];


/*--------------------------------------------------------------------------------------------------
*
* Key derivation strings.
*
*-------------------------------------------------------------------------------------------------*/
#define DATA_ENC_KEYS                   "data"
#define NAME_ENC_KEYS                   "names"
#define FILE_LABEL                      "files"


/*--------------------------------------------------------------------------------------------------
*
* Fixed nonce for use when keys are only ever used once.
*
*-------------------------------------------------------------------------------------------------*/
const uint8_t FixedNonce[] = {0x81, 0x88, 0x77, 0x9a, 0xe0, 0x81, 0xc6, 0x9b, 0x4f, 0x11, 0x15, 0x5a};


/*--------------------------------------------------------------------------------------------------
*
* Gets the base name of a path.
*
* @return
*       The base name.
*
*-------------------------------------------------------------------------------------------------*/
static const char* Basename
(
    const char* pathPtr                 ///< [IN] Path name.
)
{
    const char* base = strrchr(pathPtr, '/');

    if (base == NULL)
    {
        return pathPtr;
    }
    return base + 1;
}


/*--------------------------------------------------------------------------------------------------
*
* Prints the help message.
*
*-------------------------------------------------------------------------------------------------*/
static void PrintHelp
(
    const char *utilNamePtr             ///< [IN] Utility name.
)
{
    printf(
        "%1$s\n"
        "Securely creates/stores usernames and passwords for multiple items (such as a websites).\n"
        "\n"
        "   Usage:\n"
        "       %1$s help\n"
        "               Prints this help message and exits.\n"
        "\n"
        "       %1$s init\n"
        "               Initializes the system.  This must be called one before any other commands.\n"
        "\n"
        "       %1$s destroy\n"
        "               Destroys all information for the system.\n"
        "\n"
        "       %1$s list\n"
        "               List all available items.\n"
        "\n"
        "       %1$s config\n"
        "               Configure the system.\n"
        "\n"
        "       %1$s create <itemName>\n"
        "               Creates a new item.\n"
        "\n"
        "       %1$s get <itemName>\n"
        "               Gets the stored info for the item.\n"
        "\n"
        "       %1$s update <itemName>\n"
        "               Updates the info for the item.\n"
        "\n"
        "       %1$s delete <itemName>\n"
        "               Deletes the item.\n",
        Basename(utilNamePtr));

    exit(EXIT_FAILURE);
}


/*--------------------------------------------------------------------------------------------------
*
* Cleanup.
*
*-------------------------------------------------------------------------------------------------*/
static void Cleanup
(
    void
)
{
    ZerorizeSensitiveBufs();
    TurnEchoOn(true);
}


/*--------------------------------------------------------------------------------------------------
*
* Cleanup secret/sensitive information.
*
*-------------------------------------------------------------------------------------------------*/
static void CleanupSignalHandler
(
    int signal                          ///< [IN] Signal that occurred.
)
{
    Cleanup();
    _exit(EXIT_FAILURE);
}


/*--------------------------------------------------------------------------------------------------
*
* Gets the master password from the standard input and check if it is correct.
*
*-------------------------------------------------------------------------------------------------*/
static void CheckMasterPwd
(
    char *masterPwdPtr,                 ///< [OUT] Password.  NULL if not needed.
    uint8_t *fileSaltPtr,               ///< [OUT] File salt.  NULL if not needed.
    uint8_t *nameSaltPtr                ///< [OUT] Name salt.  NULL if not needed.
)
{
    char *pwdPtr = masterPwdPtr;
    if (masterPwdPtr == NULL)
    {
        // Use a local buffer.
        pwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    }

    uint8_t *encKeyPtr = GetSensitiveBuf(KEY_SIZE);
    uint8_t *cfgDataPtr = GetSensitiveBuf(CONFIG_DATA_SIZE);

    // Read the system file data first.
    int fd = OpenFile(SystemPath);
    CORRUPT_IF(fd == -1, "Could not open system file.");

    // Read filename salt.
    if (fileSaltPtr == NULL)
    {
        INTERNAL_ERR_IF(lseek(fd, SALT_SIZE, SEEK_CUR) == -1, "Could not seek file.  %m.");
    }
    else
    {
        INTERNAL_ERR_IF(!ReadExactBuf(fd, fileSaltPtr, SALT_SIZE), "Could not read filename salt.");
    }

    // Read encryption salt.
    if (nameSaltPtr == NULL)
    {
        INTERNAL_ERR_IF(lseek(fd, SALT_SIZE, SEEK_CUR) == -1, "Could not seek file.  %m.");
    }
    else
    {
        INTERNAL_ERR_IF(!ReadExactBuf(fd, nameSaltPtr, SALT_SIZE), "Could not read name salt.");
    }

    // Read everything else.
    uint8_t salt[SALT_SIZE];
    uint8_t tag[TAG_SIZE];
    uint8_t ct[CONFIG_DATA_SIZE];
    size_t ctSize = sizeof(ct);

    CORRUPT_IF(!ReadExactBuf(fd, salt, sizeof(salt)) ||
               !ReadExactBuf(fd, tag, sizeof(tag)) ||
               !ReadBuf(fd, ct, &ctSize),
               "Could not read config data.");

    // Read the master password.
    size_t backOffSecs = 1;
    PRINT("Please enter your master password:");

    while (1)
    {
        GetPassword(pwdPtr, MAX_PASSWORD_SIZE);

        printf("Thinking...");
        fflush(stdout);

        // Check if the password is correct.
        INTERNAL_ERR_IF(!DeriveKey(pwdPtr, salt, sizeof(salt), DATA_ENC_KEYS, encKeyPtr, KEY_SIZE),
                        "Could not derive config encryption key.");

        if (Decrypt(encKeyPtr, FixedNonce, ct, cfgDataPtr, ctSize, tag))
        {
            LoadPwdGenCfg(cfgDataPtr);
            break;
        }

        // Backoff timer.
        int i = 0;
        for (i = 0; i < backOffSecs; i++)
        {
            putchar('.');
            fflush(stdout);
            sleep(1);
        }

        backOffSecs = 2*backOffSecs;

        PRINT("\nMaster password is incorrect.");
        PRINT("Try again:");
    }

    // Clean up.
    ReleaseSensitiveBuf(encKeyPtr);
    ReleaseSensitiveBuf(cfgDataPtr);

    if (masterPwdPtr == NULL)
    {
        // Release the local buffer.
        ReleaseSensitiveBuf(pwdPtr);
    }

    if (fd != -1)
    {
        close(fd);
    }
}


/*--------------------------------------------------------------------------------------------------
*
* Get item path.
*
*-------------------------------------------------------------------------------------------------*/
static void GetItemPath
(
    const char *itemNamePtr,            ///< [IN] Item name.
    const char *masterPwdPtr,           ///< [IN] Master password.
    const uint8_t *fileSaltPtr,         ///< [IN] Filename salt.
    char *pathPtr                       ///< [OUT] Item path buffer.
)
{
    // Build a label that concatenates the item name with the file label.
    size_t labelSize = MAX_ITEM_NAME_SIZE + sizeof(FILE_LABEL);
    char *labelPtr = GetSensitiveBuf(labelSize);

    INTERNAL_ERR_IF(snprintf(labelPtr, labelSize, "%s%s", itemNamePtr, FILE_LABEL) >= labelSize,
                    "Item name too long.");

    // Derive the file name.
    char *fileNamePtr = GetSensitiveBuf(FILENAME_SIZE);

    INTERNAL_ERR_IF(!DeriveName(masterPwdPtr, fileSaltPtr, SALT_SIZE, labelPtr,
                                fileNamePtr, FILENAME_SIZE),
                    "Could not derive file name.");

    // Check if the file exists.
    INTERNAL_ERR_IF(snprintf(pathPtr, PATH_MAX, "%s/%s", StoragePath, fileNamePtr) >= PATH_MAX,
                    "Path to storage location is too long.");

    ReleaseSensitiveBuf(fileNamePtr);

    PRINT("OK");
}


/*--------------------------------------------------------------------------------------------------
*
* Get a token from the str.  Tokens are separated by newlines.  The first invocation of this must
* include the str value, subsequent invocations should be called with NULL in place of str.
*
*-------------------------------------------------------------------------------------------------*/
static void GetToken
(
    const char *str,            ///< [IN] String to parse.
    bool last,                  ///< [IN] true if this should be the last token in str.
    char *bufPtr,               ///< [OUT] Buffer to hold token.
    size_t bufSize              ///< [IN] Buffer size.
)
{
    static const char *tokenPtr;

    if (str != NULL)
    {
        tokenPtr = str;
    }

    char *sepPtr = strchrnul(tokenPtr, '\n');
    CORRUPT_IF(last != (*sepPtr == '\0'), "Unexpected number of tokens.");

    size_t tokenSize = sepPtr - tokenPtr;
    CORRUPT_IF(tokenSize >= bufSize, "Token is too long.");

    memcpy(bufPtr, tokenPtr, tokenSize);
    bufPtr[tokenSize] = '\0';
    CORRUPT_IF(!IsPrintable(bufPtr, NULL), "Invalid token.");

    tokenPtr += tokenSize + 1;
}


/*--------------------------------------------------------------------------------------------------
*
* Read an item's data.
*
*-------------------------------------------------------------------------------------------------*/
static void ReadItem
(
    const char *pathPtr,                ///< [IN] Item file path.
    const char* masterPwdPtr,           ///< [IN] Master password.
    char *usernamePtr,                  ///< [OUT] Username.
    char *pwdPtr,                       ///< [OUT] Password.
    char *otherInfoPtr                  ///< [OUT] Password.
)
{
    // Read the salt, tag and ciphertext from the file.
    uint8_t salt[SALT_SIZE];
    uint8_t tag[TAG_SIZE];
    uint8_t ct[ITEM_SIZE];

    int fd = OpenFile(pathPtr);
    CORRUPT_IF(fd < 0, "Could not open file.  %m.");

    INTERNAL_ERR_IF(lseek(fd, NONCE_SIZE + TAG_SIZE + MAX_ITEM_NAME_SIZE, SEEK_CUR) == -1,
                    "Could not seek file.  %m.");

    CORRUPT_IF(!ReadExactBuf(fd, salt, sizeof(salt)), "Could not read salt.");
    CORRUPT_IF(!ReadExactBuf(fd, tag, sizeof(tag)), "Could not read tag.");
    CORRUPT_IF(!ReadExactBuf(fd, ct, sizeof(ct)), "Could not read ciphertext.");

    close(fd);

    // Derive the encryption key.
    char *itemDataPtr = GetSensitiveBuf(ITEM_SIZE);
    uint8_t *encKeyPtr = GetSensitiveBuf(KEY_SIZE);

    CORRUPT_IF(!DeriveKey(masterPwdPtr, salt, sizeof(salt), DATA_ENC_KEYS, encKeyPtr, KEY_SIZE),
               "Could not derive encryption key.");

    // Decrypt the ciphertext.
    CORRUPT_IF(!Decrypt(encKeyPtr, FixedNonce, ct, (uint8_t*)itemDataPtr, sizeof(ct), tag),
               "Item data is corrupted and cannot be read.");
    ReleaseSensitiveBuf(encKeyPtr);

    // Read the item name.
    GetToken(itemDataPtr, false, usernamePtr, MAX_USERNAME_SIZE);
    GetToken(NULL, false, pwdPtr, MAX_PASSWORD_SIZE);
    GetToken(NULL, true, otherInfoPtr, MAX_OTHER_INFO_SIZE);

    ReleaseSensitiveBuf(itemDataPtr);
}


/*--------------------------------------------------------------------------------------------------
*
* Read an item's encrypted name and tag.
*
*-------------------------------------------------------------------------------------------------*/
static void ReadItemEncryptedName
(
    const char *pathPtr,                ///< [IN] Item file path.
    uint8_t *noncePtr,                  ///< [OUT] Nonce.
    uint8_t *tagPtr,                    ///< [OUT] Tag.
    uint8_t *encNamePtr                 ///< [OUT] Encrypted name.
)
{
    int fd = OpenFile(pathPtr);
    CORRUPT_IF(fd < 0, "Could not open file.  %m.");

    CORRUPT_IF(!ReadExactBuf(fd, noncePtr, NONCE_SIZE), "Could not read nonce.");
    CORRUPT_IF(!ReadExactBuf(fd, tagPtr, TAG_SIZE), "Could not read tag.");
    CORRUPT_IF(!ReadExactBuf(fd, encNamePtr, MAX_ITEM_NAME_SIZE), "Could not read encrypted name.");
    close(fd);
}


/*--------------------------------------------------------------------------------------------------
*
* Show summary of item data.
*
*-------------------------------------------------------------------------------------------------*/
static void ShowSummary
(
    const char *itemNamePtr,            ///< [IN] Item name.
    const char *usernamePtr,            ///< [IN] Username.
    const char *pwdPtr,                 ///< [IN] Password.
    const char *otherInfoPtr            ///< [IN] Other info.
)
{
    // See if the user would like to see the password.
    PRINT("Do you want to see the password [y/N]?");
    bool showPassword = GetYesNo(false);

    PRINT("OK, here is what we have.\n");
    PRINT("Item: '%s'", itemNamePtr);
    PRINT("Username: '%s'", usernamePtr);

    if (showPassword)
    {
        PRINT("Password: '%s'", pwdPtr);
    }
    else
    {
        PRINT("Password: *****");
    }

    PRINT("Other info: '%s'\n", otherInfoPtr);
}


/*--------------------------------------------------------------------------------------------------
*
* Encrypt item data.  Item data will always be padded out to ITEM_SIZE before encryption so the
* ciphertext is always ITEM_SIZE.
*
*-------------------------------------------------------------------------------------------------*/
static void EncryptItem
(
    const uint8_t *encKeyPtr,           ///< [IN] Encryption key.  Assumed to be KEY_SIZE.
    const char *usernamePtr,            ///< [IN] Username.
    const char *pwdPtr,                 ///< [IN] Password.
    const char *otherInfoPtr,           ///< [IN] Other info.
    uint8_t *ctPtr,                     ///< [OUT] Ciphertext.  Assumed to be ITEM_SIZE.
    uint8_t *tagPtr                     ///< [OUT] Tag.  Assumed to be TAG_SIZE.
)
{
    char *itemDataPtr = GetSensitiveBuf(ITEM_SIZE);
    memset(itemDataPtr, '\0', ITEM_SIZE);

    size_t itemDataLen = snprintf(itemDataPtr, ITEM_SIZE, "%s\n%s\n%s",
                                  usernamePtr, pwdPtr, otherInfoPtr);
    INTERNAL_ERR_IF(itemDataLen >= ITEM_SIZE, "Item data too large.");

    INTERNAL_ERR_IF(!Encrypt(encKeyPtr, FixedNonce, (uint8_t*)itemDataPtr, ctPtr, ITEM_SIZE, tagPtr),
                    "Could not encrypt data.");

    ReleaseSensitiveBuf(itemDataPtr);
}


/*--------------------------------------------------------------------------------------------------
*
* Encrypt name.  Name will always be padded out to MAX_ITEM_NAME_SIZE before encryption so the
* ciphertext is always MAX_ITEM_NAME_SIZE.
*
*-------------------------------------------------------------------------------------------------*/
static void EncryptName
(
    const uint8_t *encKeyPtr,           ///< [IN] Encryption key.  Assumed to be KEY_SIZE.
    const uint8_t *nonceptr,            ///< [IN] Random nonce.
    const char *itemNamePtr,            ///< [IN] Item name.
    uint8_t *ctPtr,                     ///< [OUT] Ciphertext.  Assumed to be MAX_ITEM_NAME_SIZE.
    uint8_t *tagPtr                     ///< [OUT] Tag.  Assumed to be TAG_SIZE.
)
{
    char *namePtr = GetSensitiveBuf(MAX_ITEM_NAME_SIZE);
    memset(namePtr, '\0', MAX_ITEM_NAME_SIZE);

    size_t len = snprintf(namePtr, MAX_ITEM_NAME_SIZE, "%s", itemNamePtr);
    INTERNAL_ERR_IF(len >= MAX_ITEM_NAME_SIZE, "Name too long.");

    INTERNAL_ERR_IF(!Encrypt(encKeyPtr, nonceptr, (uint8_t*)namePtr, ctPtr, MAX_ITEM_NAME_SIZE,
                             tagPtr),
                    "Could not encrypt data.");

    ReleaseSensitiveBuf(namePtr);
}


/*--------------------------------------------------------------------------------------------------
*
* Check if the item name is valid.
*
* @return
*       true if valid.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
static bool IsItemNameValid
(
    const char* itemNamePtr
)
{
    size_t itemNameLen;

    if (!IsPrintable(itemNamePtr, &itemNameLen))
    {
        return false;
    }

    if ( (itemNameLen <= 0) || (itemNameLen > MAX_ITEM_NAME_SIZE) )
    {
        return false;
    }

    return true;
}


/*--------------------------------------------------------------------------------------------------
*
* Get username from the user.
*
*-------------------------------------------------------------------------------------------------*/
static void GetNewUsername
(
    char* bufPtr,
    size_t bufSize
)
{
    PRINT("Please enter the username for this item:");
    GetLine(bufPtr, bufSize);
    HALT_IF(!IsPrintable(bufPtr, NULL), "Username is invalid.");
}


/*--------------------------------------------------------------------------------------------------
*
* Get password from the user.
*
*-------------------------------------------------------------------------------------------------*/
static void GetNewPassword
(
    char* bufPtr,
    size_t bufSize
)
{
    PRINT("Would you like to generate the password [Y/n]?");
    if (GetYesNo(true))
    {
        GeneratePassword(bufPtr, bufSize);
    }
    else
    {
        PRINT("OK, please enter the password you want to use:");
        GetPassword(bufPtr, bufSize);
    }
}


/*--------------------------------------------------------------------------------------------------
*
* Get other info from the user.
*
*-------------------------------------------------------------------------------------------------*/
static void GetNewOtherInfo
(
    char* bufPtr,
    size_t bufSize
)
{
    PRINT("Enter other info:");
    GetLine(bufPtr, bufSize);
    HALT_IF(!IsPrintable(bufPtr, NULL), "Info contains invalid characters.");
}


/*--------------------------------------------------------------------------------------------------
*
* Write item file.
*
*-------------------------------------------------------------------------------------------------*/
static void WriteItemFile
(
    int fd,                             ///< [IN] File descriptor to write to.
    const uint8_t *nameNoncePtr,        ///< [IN] Name nonce.  Assumed to be NONCE_SIZE.
    const uint8_t *nameTagPtr,          ///< [IN] Name tag.  Assumed to be TAG_SIZE.
    const uint8_t *nameCtPtr,           ///< [IN] Name ciphertext. Assumed to be MAX_ITEM_NAME_SIZE.
    const uint8_t *saltPtr,             ///< [IN] Salt. Assumed to be SALT_SIZE.
    const uint8_t *tagPtr,              ///< [IN] Tag.  Assumed to be TAG_SIZE.
    const uint8_t *itemCtPtr            ///< [IN] Item ciphertext.  Assumed to be ITEM_SIZE.
)
{
    INTERNAL_ERR_IF(!WriteBuf(fd, nameNoncePtr, NONCE_SIZE), "Could not write name nonce.");
    INTERNAL_ERR_IF(!WriteBuf(fd, nameTagPtr, TAG_SIZE), "Could not write name tag.");
    INTERNAL_ERR_IF(!WriteBuf(fd, nameCtPtr, MAX_ITEM_NAME_SIZE), "Could not write name ciphertext.");
    INTERNAL_ERR_IF(!WriteBuf(fd, saltPtr, SALT_SIZE), "Could not write salt.");
    INTERNAL_ERR_IF(!WriteBuf(fd, tagPtr, TAG_SIZE), "Could not write tag.");
    INTERNAL_ERR_IF(!WriteBuf(fd, itemCtPtr, ITEM_SIZE), "Could not write ciphertext.");
}


/*--------------------------------------------------------------------------------------------------
*
* Write system file.
*
*-------------------------------------------------------------------------------------------------*/
static void WriteSystemFile
(
    int fd,                             ///< [IN] File descriptor to write to.
    const uint8_t *fileSaltPtr,         ///< [IN] Filename salt.
    const uint8_t *nameSaltPtr,         ///< [IN] Name salt.
    const uint8_t *saltPtr,             ///< [IN] Salt.
    const uint8_t *tagPtr,              ///< [IN] Tag.
    const uint8_t *cfgCtPtr             ///< [IN] Config ciphertext.  Assumed to be CONFIG_DATA_SIZE.
)
{
    INTERNAL_ERR_IF(!WriteBuf(fd, fileSaltPtr, SALT_SIZE), "Could not write filename salt.");
    INTERNAL_ERR_IF(!WriteBuf(fd, nameSaltPtr, SALT_SIZE), "Could not write name salt.");
    INTERNAL_ERR_IF(!WriteBuf(fd, saltPtr, SALT_SIZE), "Could not write salt.");
    INTERNAL_ERR_IF(!WriteBuf(fd, tagPtr, TAG_SIZE), "Could not write tag.");
    INTERNAL_ERR_IF(!WriteBuf(fd, cfgCtPtr, CONFIG_DATA_SIZE), "Could not write config ciphertext.");
}


/*--------------------------------------------------------------------------------------------------
*
* Initialize the system.
*
* Creates the storage directory and the encrypted system file.
*
*-------------------------------------------------------------------------------------------------*/
static void Init
(
    void
)
{
    uint8_t *encKeyPtr = GetSensitiveBuf(KEY_SIZE);
    uint8_t *cfgDataPtr = GetSensitiveBuf(CONFIG_DATA_SIZE);
    char *masterPwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    char *masterPwd2Ptr = GetSensitiveBuf(MAX_PASSWORD_SIZE);

    // Check if the system has already been initialized.
    HALT_IF(DoesFileExist(SystemPath), "The system has already been initialized.");

    // Get the serialized config data.
    GetSerializedPwdGenCfgData(cfgDataPtr);

    // Get random salts.
    uint8_t salt[SALT_SIZE];
    uint8_t fileSalt[SALT_SIZE];
    uint8_t nameSalt[SALT_SIZE];
    GetRandom(salt, sizeof(salt));
    GetRandom(fileSalt, sizeof(fileSalt));
    GetRandom(nameSalt, sizeof(nameSalt));

    // Get the master password.
    PRINT("Create your master password.  This should be something very difficult to guess but\n"
          "memorable for you.  If you forget your master password you will lose access to all of\n"
          "your stored items.\n"
          "Please enter your master password:");
    GetPassword(masterPwdPtr, MAX_PASSWORD_SIZE);

    PRINT("Confirm master password:");
    GetPassword(masterPwd2Ptr, MAX_PASSWORD_SIZE);

    HALT_IF(strcmp(masterPwdPtr, masterPwd2Ptr) != 0, "Passwords do not match.");
    ReleaseSensitiveBuf(masterPwd2Ptr);

    // Derive the encryption key for the system file.
    INTERNAL_ERR_IF(!DeriveKey(masterPwdPtr, salt, sizeof(salt), DATA_ENC_KEYS, encKeyPtr, KEY_SIZE),
                    "Could not derive system file encryption key.");

    ReleaseSensitiveBuf(masterPwdPtr);

    // Encrypt config data.
    uint8_t ct[CONFIG_DATA_SIZE];
    uint8_t tag[TAG_SIZE];
    INTERNAL_ERR_IF(!Encrypt(encKeyPtr, FixedNonce, cfgDataPtr, ct, sizeof(ct), tag),
                    "Could not encrypt config data.");

    ReleaseSensitiveBuf(encKeyPtr);
    ReleaseSensitiveBuf(cfgDataPtr);

    // Create the storage location.
    INTERNAL_ERR_IF(mkdir(StoragePath, S_IRWXU) != 0, "Could not create %s.  %m.", StoragePath);

    // Create the system file.
    int fd = CreateFile(SystemPath);
    INTERNAL_ERR_IF(fd < 0, "Could not create system file.  %m.");
    WriteSystemFile(fd, fileSalt, nameSalt, salt, tag, ct);
    close(fd);

    PRINT("OK all set.");
}


/*--------------------------------------------------------------------------------------------------
*
* Destroy the system.
*
*-------------------------------------------------------------------------------------------------*/
static void Destroy
(
    void
)
{
    // Check if the system has been initialized.
    HALT_IF(!DoesFileExist(SystemPath), "The system has not been initialized.");

    PRINT("Do you really want to delete all your data [y/N]?");
    if (!GetYesNo(false))
    {
        return;
    }

    PRINT("Are you sure? You will lose access to all your data [y/N]?");
    if (!GetYesNo(false))
    {
        return;
    }

    CheckMasterPwd(NULL, NULL, NULL);

    INTERNAL_ERR_IF(!DeleteDir(StoragePath), "Error deleting data.");

    PRINT("OK, everything is gone.");
}


/*--------------------------------------------------------------------------------------------------
*
* List all items.
*
*-------------------------------------------------------------------------------------------------*/
static void List
(
    void
)
{
}


/*--------------------------------------------------------------------------------------------------
*
* Configure the system.
*
*-------------------------------------------------------------------------------------------------*/
static void Config
(
    void
)
{
    // Check if the system has been initialized.
    HALT_IF(!DoesFileExist(SystemPath), "The system has not been initialized.");

    uint8_t fileSalt[SALT_SIZE];
    uint8_t nameSalt[SALT_SIZE];
    char *masterPwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    CheckMasterPwd(masterPwdPtr, fileSalt, nameSalt);

    // Get new random salt.
    uint8_t salt[SALT_SIZE];
    GetRandom(salt, sizeof(salt));

    // Derive a new encryption key for the system file.
    uint8_t *encKeyPtr = GetSensitiveBuf(KEY_SIZE);
    INTERNAL_ERR_IF(!DeriveKey(masterPwdPtr, salt, sizeof(salt), DATA_ENC_KEYS, encKeyPtr, KEY_SIZE),
                    "Could not derive system file encryption key.");
    ReleaseSensitiveBuf(masterPwdPtr);

    PRINT("OK");

    ShowPwdGenConfig();

    PRINT("Use numbers when generating passwords [Y/n]?");
    PwdGenUseNums(GetYesNo(true));

    PRINT("Use letters when generating passwords [Y/n]?");
    PwdGenUseLetters(GetYesNo(true));

    PRINT("Use special characters when generating passwords [Y/n]?");
    PwdGenUseSpecialChars(GetYesNo(true));

    PRINT("Set generated password length [%u-%u]", MIN_PASSWORD_LEN, MAX_PASSWORD_LEN);
    PwdGenLen(GetUnsignedInt(MIN_PASSWORD_LEN, MAX_PASSWORD_LEN));

    uint8_t *cfgDataPtr = GetSensitiveBuf(CONFIG_DATA_SIZE);
    GetSerializedPwdGenCfgData(cfgDataPtr);

    // Encrypt config data.
    uint8_t ct[CONFIG_DATA_SIZE];
    uint8_t tag[TAG_SIZE];
    INTERNAL_ERR_IF(!Encrypt(encKeyPtr, FixedNonce, cfgDataPtr, ct, sizeof(ct), tag),
                    "Could not encrypt config data.");

    ReleaseSensitiveBuf(encKeyPtr);
    ReleaseSensitiveBuf(cfgDataPtr);

    // Create a new system file as a temp file.
    int fd = CreateFile(TempPath);
    INTERNAL_ERR_IF(fd < 0, "Could not create config file.  %m.");
    WriteSystemFile(fd, fileSalt, nameSalt, salt, tag, ct);
    close(fd);

    // Relink the temp file.
    INTERNAL_ERR_IF(rename(TempPath, SystemPath) != 0, "Could not save updates.  %m.");

    PRINT("Done.");
}


/*--------------------------------------------------------------------------------------------------
*
* Get an item.
*
*-------------------------------------------------------------------------------------------------*/
static void GetItem
(
    const char *itemNamePtr
)
{
    char *pathPtr = GetSensitiveBuf(PATH_MAX);
    char *masterPwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    char *usernamePtr = GetSensitiveBuf(MAX_USERNAME_SIZE);
    char *pwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    char *otherInfoPtr = GetSensitiveBuf(MAX_OTHER_INFO_SIZE);

    // Check item name.
    HALT_IF(!IsItemNameValid(itemNamePtr), "Item name is invalid.");

    // Check if the system has been initialized.
    HALT_IF(!DoesFileExist(SystemPath), "The system has not been initialized.");

    // Get the master password.
    uint8_t fileSalt[SALT_SIZE];
    CheckMasterPwd(masterPwdPtr, fileSalt, NULL);

    // Check if the item exist.
    GetItemPath(itemNamePtr, masterPwdPtr, fileSalt, pathPtr);
    HALT_IF(!DoesFileExist(pathPtr), "Item doesn't exist.");

    // Read item data.
    ReadItem(pathPtr, masterPwdPtr, usernamePtr, pwdPtr, otherInfoPtr);
    ReleaseSensitiveBuf(masterPwdPtr);
    ReleaseSensitiveBuf(pathPtr);

    // Show summary.
    ShowSummary(itemNamePtr, usernamePtr, pwdPtr, otherInfoPtr);
    ReleaseSensitiveBuf(usernamePtr);
    ReleaseSensitiveBuf(otherInfoPtr);
    ReleaseSensitiveBuf(pwdPtr);
}


/*--------------------------------------------------------------------------------------------------
*
* Create a new item.
*
*-------------------------------------------------------------------------------------------------*/
static void CreateNewItem
(
    const char *itemNamePtr
)
{
    char *pathPtr = GetSensitiveBuf(PATH_MAX);
    char *masterPwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    char *usernamePtr = GetSensitiveBuf(MAX_USERNAME_SIZE);
    char *pwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    char *otherInfoPtr = GetSensitiveBuf(MAX_OTHER_INFO_SIZE);
    uint8_t* encKeyPtr = GetSensitiveBuf(KEY_SIZE);
    uint8_t* nameEncKeyPtr = GetSensitiveBuf(KEY_SIZE);

    // Check item name.
    HALT_IF(!IsItemNameValid(itemNamePtr), "Item name is invalid.");

    // Check if the system has been initialized.
    HALT_IF(!DoesFileExist(SystemPath), "The system has not been initialized.");

    // Get the master password and the system salts.
    uint8_t fileSalt[SALT_SIZE];
    uint8_t nameSalt[SALT_SIZE];
    CheckMasterPwd(masterPwdPtr, fileSalt, nameSalt);

    // Check if the item exist.
    GetItemPath(itemNamePtr, masterPwdPtr, fileSalt, pathPtr);
    HALT_IF(DoesFileExist(pathPtr), "Item already exists.");

    // Derive the item encryption key.
    uint8_t salt[SALT_SIZE];
    GetRandom(salt, sizeof(salt));

    INTERNAL_ERR_IF(!DeriveKey(masterPwdPtr, salt, sizeof(salt), DATA_ENC_KEYS, encKeyPtr, KEY_SIZE),
                    "Could not get encryption key.");

    // Derive the name encryption key.
    INTERNAL_ERR_IF(!DeriveKey(masterPwdPtr, nameSalt, sizeof(nameSalt),
                               NAME_ENC_KEYS, nameEncKeyPtr, KEY_SIZE),
                    "Could not get encryption key.");

    ReleaseSensitiveBuf(masterPwdPtr);

    // Get data.
    GetNewUsername(usernamePtr, MAX_USERNAME_SIZE);
    GetNewPassword(pwdPtr, MAX_PASSWORD_SIZE);
    GetNewOtherInfo(otherInfoPtr, MAX_OTHER_INFO_SIZE);

    // Encrypt the data.
    uint8_t ct[ITEM_SIZE];
    uint8_t tag[TAG_SIZE];
    EncryptItem(encKeyPtr, usernamePtr, pwdPtr, otherInfoPtr, ct, tag);
    ReleaseSensitiveBuf(encKeyPtr);

    // Encrypt the item name.
    uint8_t nameCt[MAX_ITEM_NAME_SIZE];
    uint8_t nameTag[TAG_SIZE];
    uint8_t nonce[NONCE_SIZE];
    GetRandom(nonce, sizeof(nonce));
    EncryptName(nameEncKeyPtr, nonce, itemNamePtr, nameCt, nameTag);
    ReleaseSensitiveBuf(nameEncKeyPtr);

    // Show summary.
    ShowSummary(itemNamePtr, usernamePtr, pwdPtr, otherInfoPtr);
    ReleaseSensitiveBuf(usernamePtr);
    ReleaseSensitiveBuf(otherInfoPtr);

    // Save item.
    PRINT("Do you want to save the item [Y/n]?");
    if (GetYesNo(true))
    {
        int fd = CreateFile(pathPtr);
        INTERNAL_ERR_IF(fd < 0, "Could not create file.  %m.");
        WriteItemFile(fd, nonce, nameTag, nameCt, salt, tag, ct);
        close(fd);

        PRINT("Saved.");
    }
    ReleaseSensitiveBuf(pathPtr);
}


/*--------------------------------------------------------------------------------------------------
*
* Update an item.
*
*-------------------------------------------------------------------------------------------------*/
static void UpdateItem
(
    const char *itemNamePtr
)
{
    char *pathPtr = GetSensitiveBuf(PATH_MAX);
    char *masterPwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    char *usernamePtr = GetSensitiveBuf(MAX_USERNAME_SIZE);
    char *pwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    char *otherInfoPtr = GetSensitiveBuf(MAX_OTHER_INFO_SIZE);
    uint8_t* encKeyPtr = GetSensitiveBuf(KEY_SIZE);

    // Check item name.
    HALT_IF(!IsItemNameValid(itemNamePtr), "Item name is invalid.");

    // Check if the system has been initialized.
    HALT_IF(!DoesFileExist(SystemPath), "The system has not been initialized.");

    // Get the master password and the system salts.
    uint8_t fileSalt[SALT_SIZE];
    CheckMasterPwd(masterPwdPtr, fileSalt, NULL);

    // Check if the item exist.
    GetItemPath(itemNamePtr, masterPwdPtr, fileSalt, pathPtr);
    HALT_IF(!DoesFileExist(pathPtr), "Item doesn't exist.");

    // Read item data.
    ReadItem(pathPtr, masterPwdPtr, usernamePtr, pwdPtr, otherInfoPtr);

    // Derive a new encryption key.
    uint8_t salt[SALT_SIZE];
    GetRandom(salt, sizeof(salt));

    INTERNAL_ERR_IF(!DeriveKey(masterPwdPtr, salt, sizeof(salt), DATA_ENC_KEYS, encKeyPtr, KEY_SIZE),
                    "Could not get encryption key.");
    ReleaseSensitiveBuf(masterPwdPtr);

    // Get new data.
    bool hasChanges = false;
    while (1)
    {
        char answer[10];
        PRINT("What do you want to update [(u)sername, (p)assword, (o)ther info, (d)one]?");
        GetLine(answer, sizeof(answer));

        if ( (strcmp("username", answer) == 0) ||
            (strcmp("Username", answer) == 0) ||
            (strcmp("u", answer) == 0) ||
            (strcmp("U", answer) == 0) )
        {
            GetNewUsername(usernamePtr, MAX_USERNAME_SIZE);
            hasChanges = true;
        }
        else if ( (strcmp("password", answer) == 0) ||
                (strcmp("Password", answer) == 0) ||
                (strcmp("p", answer) == 0) ||
                (strcmp("P", answer) == 0) )
        {
            GetNewPassword(pwdPtr, MAX_PASSWORD_SIZE);
            hasChanges = true;
        }
        else if ( (strcmp("other info", answer) == 0) ||
                (strcmp("Other info", answer) == 0) ||
                (strcmp("o", answer) == 0) ||
                (strcmp("O", answer) == 0) )
        {
            GetNewOtherInfo(otherInfoPtr, MAX_OTHER_INFO_SIZE);
            hasChanges = true;
        }
        else if ( (strcmp("done", answer) == 0) ||
                (strcmp("Done", answer) == 0) ||
                (strcmp("d", answer) == 0) ||
                (strcmp("D", answer) == 0) )
        {
            break;
        }
        else
        {
            PRINT("I don't understand.");
        }
    }

    if (!hasChanges)
    {
        ReleaseSensitiveBuf(usernamePtr);
        ReleaseSensitiveBuf(pwdPtr);
        ReleaseSensitiveBuf(otherInfoPtr);
        ReleaseSensitiveBuf(encKeyPtr);
        ReleaseSensitiveBuf(pathPtr);
        PRINT("No changes.");
        return;
    }

    // Encrypt the data.
    uint8_t ct[ITEM_SIZE];
    uint8_t tag[TAG_SIZE];
    EncryptItem(encKeyPtr, usernamePtr, pwdPtr, otherInfoPtr, ct, tag);
    ReleaseSensitiveBuf(encKeyPtr);

    // Show summary.
    ShowSummary(itemNamePtr, usernamePtr, pwdPtr, otherInfoPtr);
    ReleaseSensitiveBuf(usernamePtr);
    ReleaseSensitiveBuf(pwdPtr);
    ReleaseSensitiveBuf(otherInfoPtr);

    // Get the original encrypted name and tag because those don't change.
    uint8_t nonce[NONCE_SIZE];
    uint8_t nameTag[SALT_SIZE];
    uint8_t encName[MAX_ITEM_NAME_SIZE];
    ReadItemEncryptedName(pathPtr, nonce, nameTag, encName);

    // Save.
    PRINT("Do you want to save the updates [Y/n]?");
    if (!GetYesNo(true))
    {
        PRINT("Discarding changes.");
        return;
    }

    // Save the updated item in a temporary file.
    int fd = CreateFile(TempPath);
    INTERNAL_ERR_IF(fd < 0, "Could not create file.  %m.");
    WriteItemFile(fd, nonce, nameTag, encName, salt, tag, ct);
    close(fd);

    // Relink the temp file.
    INTERNAL_ERR_IF(rename(TempPath, pathPtr) != 0, "Could not save updates.  %m.");
    ReleaseSensitiveBuf(pathPtr);

    PRINT("Updates saved.");
}


/*--------------------------------------------------------------------------------------------------
*
* Delete an item.
*
*-------------------------------------------------------------------------------------------------*/
static void DeleteItem
(
    const char *itemNamePtr
)
{
    // Check item name.
    HALT_IF(!IsItemNameValid(itemNamePtr), "Item name is invalid.");

    // Check if the system has been initialized.
    HALT_IF(!DoesFileExist(SystemPath), "The system has not been initialized.");

    // Get the master password and the system salts.
    char *masterPwdPtr = GetSensitiveBuf(MAX_PASSWORD_SIZE);
    uint8_t fileSalt[SALT_SIZE];
    CheckMasterPwd(masterPwdPtr, fileSalt, NULL);

    // Check if the item exist.
    char *pathPtr = GetSensitiveBuf(PATH_MAX);

    GetItemPath(itemNamePtr, masterPwdPtr, fileSalt, pathPtr);
    HALT_IF(!DoesFileExist(pathPtr), "Item doesn't exist.");
    ReleaseSensitiveBuf(masterPwdPtr);

    // Confirm delete.
    PRINT("Are you sure you want to delete this item [y/N]?");
    if (!GetYesNo(false))
    {
        return;
    }

    // Delete the file.
    INTERNAL_ERR_IF(unlink(pathPtr) != 0, "Could not delete item.  %m.");
    ReleaseSensitiveBuf(pathPtr);

    PRINT("Item deleted.");
}


int main(int argc, char* argv[])
{
    // Prevent memory swaps for the entire program.
    INTERNAL_ERR_IF(mlockall(MCL_CURRENT | MCL_FUTURE) != 0, "Could not lock memory.");

    // Setup signal catcher to cleanup memory in case of unexpected termination.
    struct sigaction sigAction = {0};
    sigAction.sa_handler = CleanupSignalHandler;

    INTERNAL_ERR_IF((sigaction(SIGABRT, &sigAction, NULL) != 0) ||
                    (sigaction(SIGALRM, &sigAction, NULL) != 0) ||
                    (sigaction(SIGBUS, &sigAction, NULL) != 0) ||
                    (sigaction(SIGFPE, &sigAction, NULL) != 0) ||
                    (sigaction(SIGHUP, &sigAction, NULL) != 0) ||
                    (sigaction(SIGILL, &sigAction, NULL) != 0) ||
                    (sigaction(SIGINT, &sigAction, NULL) != 0) ||
                    (sigaction(SIGIO, &sigAction, NULL) != 0) ||
                    (sigaction(SIGIOT, &sigAction, NULL) != 0) ||
                    (sigaction(SIGPIPE, &sigAction, NULL) != 0) ||
                    (sigaction(SIGPOLL, &sigAction, NULL) != 0) ||
                    (sigaction(SIGPROF, &sigAction, NULL) != 0) ||
                    (sigaction(SIGPWR, &sigAction, NULL) != 0) ||
                    (sigaction(SIGQUIT, &sigAction, NULL) != 0) ||
                    (sigaction(SIGSEGV, &sigAction, NULL) != 0) ||
                    (sigaction(SIGSTKFLT, &sigAction, NULL) != 0) ||
                    (sigaction(SIGSYS, &sigAction, NULL) != 0) ||
                    (sigaction(SIGTERM, &sigAction, NULL) != 0) ||
                    (sigaction(SIGTRAP, &sigAction, NULL) != 0) ||
                    (sigaction(SIGUSR1, &sigAction, NULL) != 0) ||
                    (sigaction(SIGUSR2, &sigAction, NULL) != 0) ||
                    (sigaction(SIGVTALRM, &sigAction, NULL) != 0) ||
                    (sigaction(SIGXCPU, &sigAction, NULL) != 0) ||
                    (sigaction(SIGXFSZ, &sigAction, NULL) != 0),
                    "Could not setup signal catcher.  %m.");

    // Setup the termination action for a regular exit as well.
    INTERNAL_ERR_IF(atexit(Cleanup) != 0, "Could not setup exit handler.");

    // Ensure echo to the terminal is turned on.
    TurnEchoOn(true);

    // Create the known paths.
    INTERNAL_ERR_IF(snprintf(StoragePath, sizeof(StoragePath),
                             "%s/%s", getenv("HOME"), STORAGE_DIR) >= sizeof(StoragePath),
                    "Storage directory path too long.");

    INTERNAL_ERR_IF(snprintf(SystemPath, sizeof(SystemPath),
                             "%s/%s", StoragePath, SYSTEM_FILE_NAME) >= sizeof(SystemPath),
                    "Config path too long.");

    INTERNAL_ERR_IF(snprintf(TempPath, sizeof(TempPath),
                             "%s/temp", StoragePath) >= sizeof(TempPath),
                    "Temp path too long.");

    // Process command line.
    switch (argc)
    {
        case 2:
            if (strcmp(argv[1], "help") == 0)
            {
                PrintHelp(argv[0]);
            }
            else if (strcmp(argv[1], "init") == 0)
            {
                Init();
            }
            else if (strcmp(argv[1], "destroy") == 0)
            {
                Destroy();
            }
            else if (strcmp(argv[1], "list") == 0)
            {
                List();
            }
            else if (strcmp(argv[1], "config") == 0)
            {
                Config();
            }
            else
            {
                PrintHelp(argv[0]);
            }
            break;

        case 3:
        {
            char *itemNamePtr = argv[2];

            if (strcmp(argv[1], "get") == 0)
            {
                GetItem(itemNamePtr);
            }
            else if (strcmp(argv[1], "create") == 0)
            {
                CreateNewItem(itemNamePtr);
            }
            else if (strcmp(argv[1], "update") == 0)
            {
                UpdateItem(itemNamePtr);
            }
            else if (strcmp(argv[1], "delete") == 0)
            {
                DeleteItem(itemNamePtr);
            }
            else
            {
                PrintHelp(argv[0]);
            }

            break;
        }

        default:
            PrintHelp(argv[0]);
    }

    return EXIT_SUCCESS;
}
