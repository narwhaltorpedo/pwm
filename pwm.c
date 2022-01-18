/*
 * Password manager command line utility.
 *
 * @section Introduction
 *
 * This utility assumes a single user.  The user can create items that contain a username, password
 * and other info.  Each item must have a unique name.
 *
 */

#include "pwm.h"


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
