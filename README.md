# PWM
PWM is a simple command line password manager that stores all data locally.

PWM is written for fun and as a way to learn about security, cryptography, github.  It should
probably not be used without further external reviews and testing.

## Overview
PWM assumes a single user.  The user can create items that contain a username, password, and other
info.  Each item must have a unique name.  Each item is stored as a file under the storage
directory.  The item filenames are derived as described below.

## System File
In addition to the item files a system file is also stored under the storage directory.  The
system file is created when the system is first initialized.  Unlike the item files the system file
is created with a fixed name.  The system contains the following information:
__________________________________________________________
| version | fileSalt | nameSalt | salt | tag | ciphertext |
----------------------------------------------------------

The ciphertext is the encrypted configuration data.  The tag is the authentication for the
ciphertext.  The salt is used to derive the encryption key to encrypt the configuration data as
follows:
     ConfigEncryptionKey = KDF(masterPassword, salt, dataEncryptionLabel)

The nameSalt is used to derive item filenames:
     itemFileName = KDF(masterPassword, nameSalt, itemName | filenameLabel)

The fileSalt is used to derive an item name encryption key:
     ItemNameEncryptionKey = KDF(masterPassword, fileSalt, filenameEncryptionLabel)

The labels in the KDF functions are fixed strings.

## Item Files
The item files contain the following information:
________________________________________________________________________________
| version |  nameNonce | nameTag | nameCiphertext | salt | tag | itemCiphertext |
--------------------------------------------------------------------------------

The itemCiphertext is the encrypted username, password and other info for the item.  The tag is the
authentication tag for the itemCiphertext.  The salt is used to derive the encryption key for the
itemCiphertext as follows:
     ItemEncryptionKey = KDF(masterPassword, salt, dataEncryptionLabel)

The nameCiphertext is the encrypted item name.  The nameTag is the authentication tag for the
nameCiphertext.  The nameNonce is the nonce when encrypting item name as follows:
     (nameCiphertext, nameTag) = Encrypt(ItemNameEncryptionKey, nameNonce)

## Rationale
The item files use a derived name to hide the item names.  This works well when creating and
getting an item as the user provides the item name.  However, this does not work when listing the
items in the system because the user does not provide the item name.  To make listing work the item
name is encrypted under an ItemNameEncryptionKey and stored in the item file.  This may not be ideal
and other options were explored such as using deterministic encryption for the file names but was
rejected due to limitations in filename lengths.

When the items are listed they are first decrypted into an array of item names and then sorted
before they are displayed.  This hides the mapping between the item names and the file mappings.

In the KDF function a fixed label is included to distinguish the use of the KDF.

Argon2id is used as the KDF because it can be tuned for time and memory requirements to slow down
master password cracking.

All memory in the process is locked which prevents swaps to disk.  This is to prevent secret data
from accidentally being stored to disk.  However, there is a limit (RLIMIT_MEMLOCK) to how much
memory a non-root process can lock which was actually found to be under the recommended memory
setting for Argon2.  The current solution is just to set the Argon2 memory as high as possible
and then tune the time value to be reasonably tolerable.  But some of these other solutions could
be explored in the future:
     - Run the program as a setuid program that would start up as root, raise the RLIMIT_MEMLOCK
       value then drop privileges.
     - Lock only certain regions of memory that are likely to contain secrets.

All fields in the system file as well as the item files are fixed sized.  For the itemCiphertext
to be a fixed length the variable length data (username, password, other info) is padded with
zeros where necessary.  Padding with zeros is unambiguous because the plaintext is treated as a
NULL-terminated string.

Chacha20poly1305 is used for data and item name encryption.  The nonce value in chacha20poly1305
is only 96 bits which can be risky to generate randomly.  This is not a problem for data
encryption because a new key is used for each invocation.  In fact for data encryption we use a
fixed nonce for this reason.  For item name encryption we generate the nonce randomly for each
invocation so maybe in the future Xchacha20poly1305 would be a better choice.

To help with zeroization of sensitive data we create a sensitive memory allocator that
automatically zerorizes the memory before freeing it.  To make this more robust we create a
termination action and a signal handler that zerorizes and frees all sensitive buffers in case of
a process termination.