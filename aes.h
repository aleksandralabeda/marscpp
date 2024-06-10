#ifndef AES_H
#define AES_H

#include <iostream>

#define TRUE            1
#define FALSE           0

#define DIR_ENCRYPT     0    /*  Are we encrypting?                         */
#define DIR_DECRYPT     1    /*  Are we decrypting?                         */
#define MODE_ECB        1    /*  Are we ciphering in ECB mode?              */
#define MODE_CBC        2    /*  Are we ciphering in CBC mode?              */
#define MODE_CFB1       3    /*  Are we ciphering in 1-bit CFB mode?        */

#define BAD_KEY_DIR      (-1)  /*  Key direction is invalid                   */
#define BAD_KEY_MAT      (-2)  /*  Key material not of correct length         */
#define BAD_KEY_INSTANCE (-3)  /*  Key passed is not valid                    */
#define BAD_CIPHER_MODE  (-4)  /*  Params struct passed to cipherInit invalid */
#define BAD_CIPHER_STATE (-5)  /*  Cipher in wrong state                      */

typedef unsigned char BYTE;

/* IBM Addition - a WORD must be 32 bits for this implementation */
typedef unsigned long WORD;

/* IBM specific defines: these parameters can be changed               */
#define NUM_MIX 8           /* number of mixing rounds per stage       */
#define NUM_ROUNDS 16       /* number of full core rounds              */
#define NUM_SETUP 7         /* number of key setup mixing rounds       */

/* IBM specific defines: these parameters are fixed for this implementation */
#define W          32       /* number of bits in a word                     */
#define NUM_DATA    4       /* data block size in words                     */
#define EKEY_WORDS (2*(NUM_DATA+NUM_ROUNDS))    /* number of subkey words   */

/* IBM modified values                                                      */
#define MAX_KEY_SIZE (EKEY_WORDS*8)  /* max ASCII char's needed for a key   */
#define MAX_IV_SIZE (NUM_DATA*4)     /* max bytes's needed for an IV        */

/*  The structure for key information */
typedef struct {
    BYTE direction; /*  Key used for encrypting or decrypting?       */
    int keyLen; /*  Length of the key in BITS                    */
    char keyMaterial[MAX_KEY_SIZE + 1]; /*  Raw key data in ASCII           */
    WORD E[EKEY_WORDS]; /* IBM addition for mars expanded key            */
} keyInstance;

/*  The structure for cipher information */
typedef struct {
    BYTE mode; /*  MODE_ECB, MODE_CBC, or MODE_CFB1             */
    BYTE IV[MAX_IV_SIZE]; /*  initial binary IV BYTE for chaining          */
    WORD CIV[NUM_DATA]; /*  IBM addition: current IV in binary WORDs     */
} cipherInstance;

/*  NIST High level function protoypes  */
int makeKey(keyInstance *key, BYTE direction, int keyLen, const char *keyMaterial);

int cipherInit(cipherInstance *cipher, BYTE mode, const char *IV);

int blockEncrypt(cipherInstance *cipher, keyInstance *key, BYTE *input,
                 int inputLen, BYTE *outBuffer);

int blockDecrypt(cipherInstance *cipher, const keyInstance *key, BYTE *input,
                 int inputLen, BYTE *outBuffer);


/* setup a mars expanded key
 *
 * k  (input) is the number of words in the key
 * kp (input) is a pointer to the array of k key words
 * ep (output) is a pointer to an array of EKEY_WORDS expanded subkey WORDs
 */
int mars_setup(int k, const WORD *kp, WORD *ep);

/* The basic mars encryption of one block (of NUM_DATA WORDS) */
void mars_encrypt(const WORD *in, WORD *out, const WORD *ep);

/* mars decryption is simply encryption in reverse */
void mars_decrypt(const WORD *in, WORD *out, const WORD *ep);

#endif // AES_H
