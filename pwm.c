/*
 * Password manager command line utility.
 *
 * @section Introduction
 *
 * This utility assumes a single user.  The user can create items that contain a username, password
 * and other info.  Each item must have a unique name.
 *
 */

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
}


int main(int argc, char* argv[])
{
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
