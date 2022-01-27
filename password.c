/*
 * Password utilities.
 *
 */

#include "pwm.h"
#include "password.h"

#include "crypto.h"


/*--------------------------------------------------------------------------------------------------
*
* Password generation configurations.
*
*-------------------------------------------------------------------------------------------------*/
static bool UseNums = true;
static bool UseLetters = true;
static bool UseSpecialChars = true;
static uint8_t PasswordLen = 25;


/*--------------------------------------------------------------------------------------------------
*
* Symbol alphabet.
*
*-------------------------------------------------------------------------------------------------*/
#define NUM_NUMS                10
#define NUM_LETTERS             52
#define NUM_SPECIAL_CHARS       30

static const char Nums[NUM_NUMS] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
static const char Letters[NUM_LETTERS] = {
    'a', 'b', 'c', 'd', 'w', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'W', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
static const char Specials[NUM_SPECIAL_CHARS] = {
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', '{', '}', ']', '\\',
    '|', ';', ':', '\'', '"', ',', '<', '.', '>', '/', '?'};

static char Symbols[NUM_NUMS + NUM_LETTERS + NUM_SPECIAL_CHARS];
static uint8_t SymCount = 0;
static uint8_t MaxSymIndex = 0;


/*--------------------------------------------------------------------------------------------------
*
* Load password generation configuration.
*
*-------------------------------------------------------------------------------------------------*/
void LoadPwdGenCfg
(
    const uint8_t *serialCfgDataPtr     ///< [IN] Serialized configuration data.  Assumed to be
                                        ///       CONFIG_DATA_SIZE.
)
{
    // Deserialize configuration.
    UseNums = serialCfgDataPtr[0];
    UseLetters = serialCfgDataPtr[1];
    UseSpecialChars = serialCfgDataPtr[2];
    PasswordLen = serialCfgDataPtr[3];

    // Build the symbols table.
    SymCount = 0;

    if (UseNums)
    {
        memcpy(Symbols + SymCount, Nums, NUM_NUMS);
        SymCount += NUM_NUMS;
    }

    if (UseLetters)
    {
        memcpy(Symbols + SymCount, Letters, NUM_LETTERS);
        SymCount += NUM_LETTERS;
    }

    if (UseSpecialChars)
    {
        memcpy(Symbols + SymCount, Specials, NUM_SPECIAL_CHARS);
        SymCount += NUM_SPECIAL_CHARS;
    }

    // Calculate the maximum symbol index modulo SymCount.
    MaxSymIndex = ((256 / SymCount) * SymCount) - 1;
}


/*--------------------------------------------------------------------------------------------------
*
* Get serialized password generation configuration data.
*
*-------------------------------------------------------------------------------------------------*/
void GetSerializedPwdGenCfgData
(
    uint8_t *bufPtr                     ///< [OUT] Buffer to store serialized configuration data.
                                        ///        Assumed to be CONFIG_DATA_SIZE.
)
{
    bufPtr[0] = UseNums ? 1 : 0;
    bufPtr[1] = UseLetters ? 1 : 0;
    bufPtr[2] = UseSpecialChars ? 1 : 0;
    bufPtr[3] = PasswordLen;
}


/*--------------------------------------------------------------------------------------------------
*
* Show current password generation configuration data.
*
*-------------------------------------------------------------------------------------------------*/
void ShowPwdGenConfig
(
    void
)
{
    PRINT("Password generation uses:");
    PRINT("  Numbers: %s", (UseNums ? "yes" : "no"));
    PRINT("  Letters: %s", (UseLetters ? "yes" : "no"));
    PRINT("  Special characters: %s", (UseSpecialChars ? "yes" : "no"));
    PRINT("  Length: %u", PasswordLen);
}


/*--------------------------------------------------------------------------------------------------
*
* Set use nums in password generation.
*
*-------------------------------------------------------------------------------------------------*/
void PwdGenUseNums
(
    bool useNums
)
{
    UseNums = useNums;
}


/*--------------------------------------------------------------------------------------------------
*
* Set use letters in password generation.
*
*-------------------------------------------------------------------------------------------------*/
void PwdGenUseLetters
(
    bool useLetters
)
{
    UseLetters = useLetters;
}


/*--------------------------------------------------------------------------------------------------
*
* Set use special characters in password generation.
*
*-------------------------------------------------------------------------------------------------*/
void PwdGenUseSpecialChars
(
    bool useSpecialChars
)
{
    UseSpecialChars = useSpecialChars;
}


/*--------------------------------------------------------------------------------------------------
*
* Set generated password length.
*
*-------------------------------------------------------------------------------------------------*/
void PwdGenLen
(
    uint8_t len
)
{
    INTERNAL_ERR_IF((len < MIN_PASSWORD_LEN) || (len > MAX_PASSWORD_LEN),
                    "Invalid password length.");
    PasswordLen = len;
}


/*--------------------------------------------------------------------------------------------------
*
* Generate a password.
*
*-------------------------------------------------------------------------------------------------*/
void GeneratePassword
(
    char* bufPtr,                       ///< [OUT] Buffer to hold password.
    size_t bufSize                      ///< [IN] Buffer size.
)
{
    uint8_t len = PasswordLen;
    if (len > bufSize - 1)
    {
        len = bufSize - 1;
    }

    uint8_t i = 0;
    while (i < len)
    {
        // Get a buffer of random data that should be enough to generate the password.
        uint8_t rand[MAX_PASSWORD_SIZE];
        GetRandom(rand, sizeof(rand));

        size_t j = 0;
        for (j = 0; j < sizeof(rand); j++)
        {
            if (rand[j] <= MaxSymIndex)
            {
                bufPtr[i++] = Symbols[rand[j] % SymCount];

                if (i >= len)
                {
                    break;
                }
            }
            // else throw away values that would cause a bias.
        }
    }

    bufPtr[len] = '\0';
}


/*--------------------------------------------------------------------------------------------------
*
* Check if the password is meets requirements.
*
* @return
*       true if successful.
*       false otherwise.
*
*-------------------------------------------------------------------------------------------------*/
bool IsPasswordValid
(
    const char *pwdPtr                  ///< [IN] Password to check.
)
{
    size_t len;

    if (!IsPrintable(pwdPtr, &len))
    {
        PRINT("Only printable characters can be used.");
        return false;
    }

    if (len < MIN_PASSWORD_LEN)
    {
        PRINT("Passwords must be at least %d characters.", MIN_PASSWORD_LEN);
        return false;
    }

    if (len > MAX_PASSWORD_LEN)
    {
        PRINT("Passwords must be at most %d characters.", MAX_PASSWORD_LEN);
        return false;
    }

    return true;
}