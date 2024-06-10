#include "aes.h"
#include <ctime>
#include <iomanip>
#include <fstream>
#include <iostream>
using namespace std;

/**
 *  The function ivt_ecb is performing an encryption and decryption test using the Electronic Codebook (ECB)
 *  mode of the MARS encryption algorithm. It tests different key sizes (128-bit, 192-bit, and 256-bit)
 *  and records the results to a file
 * @param ctbuf
 * @param outbuf
 * @param decipher
 * @param encipher
 * @param keyin
 */
void ivt_ecb(BYTE ctbuf[16], BYTE outbuf[16], cipherInstance &decipher, cipherInstance &encipher, keyInstance &keyin) {
    BYTE ptbuf[16];
    char akey[MAX_KEY_SIZE + 1];

    /*
     *Set Up the File: It creates a file named "ecb_ivt.txt" and writes some introductory
     *information about the test.
     */
    // Intermediate Value Test -> ecb_ivt.txt
    ofstream file("ecb_ivt.txt");
    file << "=========================\n\n";
    file << "FILENAME:  \"ecb_ivt.txt\"\n\n";
    file << "Electronic Codebook (ECB) Mode\n";
    file << "Intermediate Values Tests\n\n";
    file << "Algorithm Name: Mars\n";
    file << "Principle Submitter: IBM\n";

    /*
    *Sets up an array of zeros to use as the plaintext.
     Prepares a key (initially all zeros) to use for encryption and decryption.*/

    // the input plaintext and key are all zeros
    for (unsigned char &i: ptbuf)
        i = 0;

    /*
        *For each key size (128-bit, 192-bit, and 256-bit):
        Encryption:
            Uses the key to encrypt the plaintext.
        Writes the key, plaintext, and resulting ciphertext to the file.
            Decryption:
        Uses the same key to decrypt the ciphertext.
        Writes the key, ciphertext, and resulting plaintext to the file.
        */

    // 128 bit keys
    for (int i = 0; i < 32; i++)
        akey[i] = '0';
    akey[32] = '\0';
    file << "\n\n==========\n\nEncryption: KEYSIZE=128\n\n";
    file << "KEY=" << akey << "\n";
    file << "PT=00000000000000000000000000000000\n";
    makeKey(&keyin,DIR_ENCRYPT, 128, akey);
    cipherInit(&encipher,MODE_ECB, nullptr);
    cipherInit(&decipher,MODE_ECB, nullptr);
    blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
    file << "CT=";
    for (int k = 0; k < 16; k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
    file << "\n\n==========\n\nDecryption: KEYSIZE=128\n\n";
    file << "KEY=" << akey << "\n";
    file << "CT=";
    for (int k = 0; k < 16; k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
    file << "\n";

    blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
    file << "PT=";
    for (int k = 0; k < 16; k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(outbuf[k]);

    // 192 bit keys
    for (int i = 0; i < 48; i++)
        akey[i] = '0';
    akey[48] = '\0';
    file << "\n\n==========\n\nEncryption: KEYSIZE=192\n\n";
    file << "KEY=" << akey << "\n";
    file << "PT=00000000000000000000000000000000\n";
    makeKey(&keyin,DIR_ENCRYPT, 192, akey);
    cipherInit(&encipher,MODE_ECB, nullptr);
    cipherInit(&decipher,MODE_ECB, nullptr);

    blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
    file << "CT=";
    for (int k = 0; k < 16; k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
    file << "\n\n==========\n\nDecryption: KEYSIZE=192\n\n";
    file << "KEY=" << akey << "\n";
    file << "CT=";
    for (int k = 0; k < 16; k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
    file << "\n";
    blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
    file << "PT=";
    for (int k = 0; k < 16; k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(outbuf[k]);

    // 256 bit keys
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    file << "\n\n==========\n\nEncryption: KEYSIZE=256\n\n";
    file << "KEY=" << akey << "\n";
    file << "PT=00000000000000000000000000000000\n";
    makeKey(&keyin,DIR_ENCRYPT, 256, akey);
    cipherInit(&encipher,MODE_ECB, nullptr);
    cipherInit(&decipher,MODE_ECB, nullptr);
    blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
    file << "CT=";
    for (int k = 0; k < 16; k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
    file << "\n\n==========\n\nDecryption: KEYSIZE=256\n\n";
    file << "KEY=" << akey << "\n";
    file << "CT=";
    for (int k = 0; k < 16; k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);

    file << "\n";
    blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
    file << "PT=";
    for (int k = 0; k < 16; k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(outbuf[k]);
    file << "\n";
    file.close();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 *Sure, I can simplify the explanation for you.
 *The key_kat function runs a series of tests to check the encryption and decryption process
 *using different keys in Electronic Codebook (ECB) mode with the MARS encryption algorithm.
 *It varies each bit of the key and logs the results to a file.
 */
void key_kat(BYTE ctbuf[16], BYTE outbuf[16], cipherInstance &decipher, cipherInstance &encipher, keyInstance &keyin) {
    BYTE ptbuf[16];
    char akey[MAX_KEY_SIZE + 1];

    // 128 bit keys
    cout << "Running KAT tests" << endl;
    ofstream file("ecb_vk.txt");
    file << "=========================\n\n";
    file << "FILENAME:  \"ecb_vk.txt\"\n\n";
    file << "Electronic Codebook (ECB) Mode\n";
    file << "Variable Key Known Answer Tests\n\n";
    file << "Algorithm Name: Mars\n";
    file << "Principle Submitter: IBM\n";
    // the input plaintext is all zeros
    for (unsigned char &i: ptbuf)
        i = 0;
    /*
        *For each key size (128-bit, 192-bit, and 256-bit):
        Varies each bit of the key (by setting one bit at a time).
        Encrypts the plaintext with the modified key.
        Decrypts the resulting ciphertext.
        Writes the key, ciphertext, and any decryption errors to the file.
      */
    // 128 bit keys
    akey[32] = '\0';
    file << "\n\n==========\n\nKEYSIZE=128\n\n";
    file << "PT=00000000000000000000000000000000\n";

    for (int i = 0; i < 32; i++) {
        for (int j = 3; j >= 0; j--) {
            for (int k = 0; k < 32; k++)
                akey[k] = '0';
            akey[i] = static_cast<char>('0' + (1 << j));
            makeKey(&keyin,DIR_ENCRYPT, 128, akey);
            cipherInit(&encipher,MODE_ECB, nullptr);
            cipherInit(&decipher,MODE_ECB, nullptr);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i * 4 + 4 - j << "\n";
            file << "KEY=" << akey << "\n";
            file << "CT=";
            for (int k = 0; k < 16; k++) {
                if (outbuf[k] != 0)
                    file << "*decryption error*\n";
                else
                    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
            }
            file << "\n";
        }
    }
    // 192 bit keys
    akey[48] = '\0';
    file << "\n\n==========\n\nKEYSIZE=192\n\n";
    file << "PT=00000000000000000000000000000000\n";

    for (int i = 0; i < 48; i++) {
        for (int j = 3; j >= 0; j--) {
            for (int k = 0; k < 48; k++)
                akey[k] = '0';
            akey[i] = static_cast<char>('0' + (1 << j));
            makeKey(&keyin,DIR_ENCRYPT, 192, akey);
            cipherInit(&encipher,MODE_ECB, nullptr);
            cipherInit(&decipher,MODE_ECB, nullptr);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i * 4 + 4 - j << "\n";
            file << "KEY=" << akey << "\n";
            file << "CT=";
            for (int k = 0; k < 16; k++) {
                if (outbuf[k] != 0)
                    file << "*decryption error*\n";
                else
                    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
            }
            file << "\n";
        }
    }
    // 256 bit keys
    akey[64] = '\0';
    file << "\n\n==========\n\nKEYSIZE=256\n\n";
    file << "PT=00000000000000000000000000000000\n";

    for (int i = 0; i < 64; i++) {
        for (int j = 3; j >= 0; j--) {
            for (int k = 0; k < 64; k++)
                akey[k] = '0';
            akey[i] = static_cast<char>('0' + (1 << j));
            akey[i] = static_cast<char>('0' + (1 << j));
            cipherInit(&encipher,MODE_ECB, nullptr);
            cipherInit(&decipher,MODE_ECB, nullptr);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i * 4 + 4 - j << "\n";
            file << "KEY=" << akey << "\n";
            file << "CT=";
            for (int k = 0; k < 16; k++) {
                if (outbuf[k] != 0)
                    file << "*decryption error*\n";
                else
                    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
            }
            file << "\n";
        }
    }
    file << "\n==========\n";
    file.close();
}

/**
 * The text_kat_var function performs Variable Text Known Answer Tests (KAT) for different
 * plaintexts and logs the results to a file named "ecb_vt.txt".
 * Additionally, it performs a series of tests to ensure that all entries in the
 * fixed S-box are used at least once, and logs these results to another file named "ecb_tbl.txt".
 * @param ctbuf
 * @param outbuf
 * @param decipher
 * @param encipher
 * @param keyin
 */
void text_kat_var(BYTE ctbuf[16], BYTE outbuf[16], cipherInstance &decipher, cipherInstance &encipher,
                  keyInstance &keyin) {
    WORD S[16] = {
        0xf20b4862, 0xcd79bde4, 0x498f7a5b, 0xcfc31f4c,
        0x354d61f3, 0x2e31fa47, 0x8c18da7f, 0xe14e831d,
        0x5de9d8d6, 0x68843750, 0xa2e71b63, 0xeff8e372,
        0x8792349d, 0x8a58369a, 0x2e9382ba, 0xa72b988f
    };

    BYTE ptbuf[16];
    char akey[MAX_KEY_SIZE + 1];

    ofstream file("ecb_vt.txt");
    file << "=========================\n\n";
    file << "FILENAME:  \"ecb_vt.txt\"\n\n";
    file << "Electronic Codebook (ECB) Mode\n";
    file << "Variable Text Known Answer Tests\n\n";
    file << "Algorithm Name: Mars\n";
    file << "Principle Submitter: IBM\n";
    /* the input key is all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    /*
      *Run Tests for Different Key Sizes (128-bit, 192-bit, and 256-bit):
    For each key size:
        Uses a fixed key.
        Varies each bit of the plaintext by setting one bit at a time.
        Encrypts the modified plaintext.
        Decrypts the resulting ciphertext.
        Logs the key, plaintext, ciphertext, and any decryption errors to the file.
      *Run Tests for S-Box Entries:
     For each key size:
        Uses a fixed key.
        Starts with an initial plaintext.
        Encrypts the plaintext and logs the results.
        Sets the next plaintext to the last ciphertext output and repeats.
     *
     */


    /* 128 bit keys */
    file << "\n\n==========\n\nKEYSIZE=128\n\n";
    file << "KEY=00000000000000000000000000000000\n";
    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            for (unsigned char &k: ptbuf)
                k = 0;
            ptbuf[i] = (1 << j);
            makeKey(&keyin,DIR_ENCRYPT, 128, akey);
            cipherInit(&encipher,MODE_ECB, nullptr);
            cipherInit(&decipher,MODE_ECB, nullptr);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i * 8 + 8 - j << "\n";
            file << "PT=";
            for (unsigned char k: ptbuf)
                file << hex << setw(2) << setfill('0') << static_cast<int>(k);
            file << "\nCT=";
            for (int k = 0; k < 16; k++) {
                if (outbuf[k] != ptbuf[k])
                    file << "*decryption error*\n";
                else
                    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
            }
        }
    }
    /* 192 bit keys */
    file << "\n\n==========\n\nKEYSIZE=192\n\n";
    file << "KEY=000000000000000000000000000000000000000000000000\n";
    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            for (unsigned char &k: ptbuf)
                k = 0;
            ptbuf[i] = (1 << j);
            makeKey(&keyin,DIR_ENCRYPT, 192, akey);
            cipherInit(&encipher,MODE_ECB, nullptr);
            cipherInit(&decipher,MODE_ECB, nullptr);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i * 8 + 8 - j << "\n";
            file << "PT=";
            for (unsigned char k: ptbuf)
                file << hex << setw(2) << setfill('0') << static_cast<int>(k);
            file << "\nCT=";
            for (int k = 0; k < 16; k++) {
                if (outbuf[k] != ptbuf[k])
                    file << "*decryption error*\n";
                else
                    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
            }
        }
    }
    /* 256 bit key */
    file << "\n\n==========\n\nKEYSIZE=256\n\n";
    file << "KEY=00000000000000000000000000000000";
    file << "00000000000000000000000000000000\n";
    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            for (unsigned char &k: ptbuf)
                k = 0;
            ptbuf[i] = (1 << j);
            makeKey(&keyin,DIR_ENCRYPT, 256, akey);
            cipherInit(&encipher,MODE_ECB, nullptr);
            cipherInit(&decipher,MODE_ECB, nullptr);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i * 8 + 8 - j << "\n";
            file << "PT=";
            for (unsigned char k: ptbuf)
                file << hex << setw(2) << setfill('0') << static_cast<int>(k);
            file << "\nCT=";
            for (int k = 0; k < 16; k++) {
                if (outbuf[k] != ptbuf[k])
                    file << "*decryption error*\n";
                else
                    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
            }
        }
    }
    file << "\n==========\n";
    file.close();

    /* Tables KAT -> ecb_tbl.txt
     * To test all Sbox entries, we fix the key to be zero, start
     * with some initial plaintext, and iterate, setting each
     * next plaintext to the last ciphertext output.  We instrumented
     * the sbox lookups, and found that after 40 such iterations, all
     * sboxes had been used at least once for each key length.
     */
    ofstream file2("ecb_tbl.txt");
    file2 << "/*  This tests all 512 entries in the fixed Sbox  */\n\n";
    file2 << "=========================\n\n";
    file2 << "FILENAME:  \"ecb_tbl.txt\"\n\n";
    file2 << "Electronic Codebook (ECB) Mode\n";
    file2 << "Tables Known Answer Tests\n\n";
    file2 << "Algorithm Name: Mars\n";
    file2 << "Principle Submitter: IBM";
    /* the input key is all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';

    /* 128 bit keys */
    file2 << "\n\n==========\n\nKEYSIZE=128\n";
    makeKey(&keyin,DIR_ENCRYPT, 128, akey);
    cipherInit(&encipher,MODE_ECB, nullptr);
    /* set some interesting starting text */
    for (unsigned char &i: ptbuf)
        i = 0;
    for (int i = 1; i < 41; i++) {
        blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
        file2 << "\n\nI=" << i << "\n";
        file2 << "KEY=00000000000000000000000000000000\n";
        file2 << "PT=";
        for (unsigned char k: ptbuf)
            file2 << hex << setw(2) << setfill('0') << static_cast<int>(k);
        file2 << "\nCT=";
        for (int k = 0; k < 16; k++)
            file2 << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
        for (int j = 0; j < 16; j++)
            ptbuf[j] = ctbuf[j];
    }
    /* 192 bit keys */
    file2 << "\n\n==========\n\nKEYSIZE=192\n";
    makeKey(&keyin,DIR_ENCRYPT, 192, akey);
    cipherInit(&encipher,MODE_ECB, nullptr);
    /* set some interesting starting text */
    for (unsigned char &i: ptbuf)
        i = 0xaa;
    for (int i = 1; i < 41; i++) {
        blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
        file2 << "\n\nI=" << i << "\n";
        file2 << "KEY=00000000000000000000000000000000";
        file2 << "0000000000000000\n";
        file2 << "PT=";
        for (unsigned char k: ptbuf)
            file2 << hex << setw(2) << setfill('0') << static_cast<int>(k);
        file2 << "\nCT=";
        for (int k = 0; k < 16; k++)
            file2 << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
        for (int j = 0; j < 16; j++)
            ptbuf[j] = ctbuf[j];
    }
    /* 256 bit keys */
    file2 << "\n\n==========\n\nKEYSIZE=256\n";
    makeKey(&keyin,DIR_ENCRYPT, 256, akey);
    cipherInit(&encipher,MODE_ECB, nullptr);
    /* set some interesting starting text */
    for (int i = 0; i < 16; i++)
        ptbuf[i] = S[i] & 0xff;
    for (int i = 1; i < 41; i++) {
        blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
        file2 << "\n\nI=" << i << "\n";
        file2 << "KEY=00000000000000000000000000000000";
        file2 << "00000000000000000000000000000000\n";
        file2 << "PT=";
        for (unsigned char k: ptbuf)
            file2 << hex << setw(2) << setfill('0') << static_cast<int>(k);
        file2 << "\nCT=";
        for (int k = 0; k < 16; k++)
            file2 << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
        for (int j = 0; j < 16; j++)
            ptbuf[j] = ctbuf[j];
    }
    file2 << "\n==========\n";
    file2.close();
}

/**
 * The function mct_ecb_encrypt performs Monte Carlo Tests for the ECB (Electronic Codebook)
 * encryption mode using different key sizes (128, 192, and 256 bits). This function tests the
 * encryption algorithm by performing a large number of iterations with the same key and
 * plaintext and then varying the key slightly based on the ciphertext results
 * @param ctbuf
 * @param encipher
 * @param keyin
 */
void mct_ecb_encrypt(BYTE ctbuf[16], cipherInstance &encipher, keyInstance &keyin) {
    //mct setup
    extern BYTE hex[];
    //file setup
    BYTE ptbuf[16];
    char akey[MAX_KEY_SIZE + 1];
    char tohex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    ofstream file("ecb_e_m.txt");
    file << "=========================\n\n";
    file << "FILENAME:  \"ecb_e_m.txt\"\n\n";
    file << "Electronic Codebook (ECB) Mode - ENCRYPTION\n";
    file << "Monte Carlo Test\n\n";
    file << "Algorithm Name: Mars\n";
    file << "Principle Submitter: IBM\n";

    /*
     *
     *
        *Monte Carlo Test Loop:

        Outer Loop (400 iterations):
        Generate a key using makeKey.

        Write the iteration number, key, and plaintext to the file.

        Inner Loop (5000 iterations):

        Encrypt the plaintext to get the ciphertext (ctbuf).
        Encrypt the ciphertext to get the next plaintext (ptbuf).
        Write the final ciphertext to the file.

        Update the key:

        For 128-bit keys: XOR the key with the plaintext.
        For 192-bit keys: The first 64 bits come from the end of ctbuf, and the remaining 128 bits from ptbuf.
        For 256-bit keys: The first 128 bits come from ctbuf, and the remaining 128 bits from ptbuf.
     *
     *
     */
    /* 128 bit keys */
    file << "\n\n=========================\n\nKEYSIZE=128\n";
    /* the starting key and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (unsigned char &i: ptbuf)
        i = 0;
    cipherInit(&encipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 128, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 32; k++)
            file << akey[k];
        file << "\nPT=";
        for (unsigned char k: ptbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        for (int k = 0; k < 5000; k++) {
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockEncrypt(&encipher, &keyin, ctbuf, 128, ptbuf);
        }
        file << "\nCT=";
        for (unsigned char k: ptbuf) {
            file << tohex[k >> 4] << tohex[k & 0x0f];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ptbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ptbuf[k] & 0x0f)];
        }
    }
    /* 192 bit keys */
    file << "\n\n=========================\n\nKEYSIZE=192\n";
    /* the starting key and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (unsigned char &i: ptbuf)
        i = 0;
    cipherInit(&encipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 192, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 48; k++)
            file << akey[k];
        file << "\nPT=";
        for (unsigned char k: ptbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        for (int k = 0; k < 5000; k++) {
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockEncrypt(&encipher, &keyin, ctbuf, 128, ptbuf);
        }
        /* ptbuf contains the last CT, and ctbuf has the prior... */
        file << "\nCT=";
        for (unsigned char k: ptbuf) {
            file << tohex[k >> 4] << tohex[k & 0x0f];
        }
        /* the first 64 bits come from the end of ctbuf, and
         * the remaining 128 bits from ptbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 8; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ctbuf[k + 8] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ctbuf[k + 8] & 0x0f)];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k + 16] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 16]))] ^ (
                                         ptbuf[k] >> 4)];
            akey[2 * k + 17] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 17]))] ^ (
                                         ptbuf[k] & 0x0f)];
        }
    }
    /* 256 bit keys */
    file << "\n\n=========================\n\nKEYSIZE=256\n";
    /* the starting key and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (unsigned char &i: ptbuf)
        i = 0;
    cipherInit(&encipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 256, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 64; k++)
            file << akey[k];
        file << "\nPT=";
        for (unsigned char k: ptbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        for (int k = 0; k < 5000; k++) {
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockEncrypt(&encipher, &keyin, ctbuf, 128, ptbuf);
        }
        /* ptbuf contains the last CT, and ctbuf has the prior... */
        file << "\nCT=";
        for (unsigned char k: ptbuf) {
            file << tohex[k >> 4] << tohex[k & 0x0f];
        }
        /* the first 128 bits come from ctbuf, and
         * the remaining 128 bits from ptbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ctbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ctbuf[k] & 0x0f)];
            akey[2 * k + 32] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 32]))] ^ (
                                         ptbuf[k] >> 4)];
            akey[2 * k + 33] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 33]))] ^ (
                                         ptbuf[k] & 0x0f)];
        }
    }
    file << "\n==========\n";
    file.close();
}

/**
 * The function mct_ecb_decrypt performs Monte Carlo Tests for the ECB (Electronic Codebook)
 * decryption mode using different key sizes (128, 192, and 256 bits). This function tests
 * the decryption algorithm by performing a large number of iterations with the same key
 * and ciphertext, then varying the key slightly based on the plaintext results.
 * @param ctbuf
 * @param decipher
 * @param encipher
 * @param keyin
 */
void mct_ecb_decrypt(BYTE ctbuf[16], cipherInstance &decipher, cipherInstance &encipher, keyInstance &keyin) {
    //mct setup
    extern BYTE hex[];

    //file setup
    BYTE ptbuf[16];
    char akey[MAX_KEY_SIZE + 1];
    char tohex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    ofstream file("ecb_d_m.txt");
    file << "=========================\n\n";
    file << "FILENAME:  \"ecb_d_m.txt\"\n\n";
    file << "Electronic Codebook (ECB) Mode - DECRYPTION\n";
    file << "Monte Carlo Test\n\n";
    file << "Algorithm Name: Mars\n";
    file << "Principle Submitter: IBM\n";

    /* 128 bit keys */
    file << "\n\n=========================\n\nKEYSIZE=128\n";
    /* the starting key and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (unsigned char &i: ptbuf)
        i = 0;
    cipherInit(&decipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_DECRYPT, 128, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 32; k++)
            file << akey[k];
        file << "\nCT=";
        for (unsigned char k: ptbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        for (int k = 0; k < 5000; k++) {
            blockDecrypt(&decipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
        }
        file << "\nPT=";
        for (unsigned char k: ptbuf) {
            file << tohex[k >> 4] << tohex[k & 0x0f];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ptbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ptbuf[k] & 0x0f)];
        }
    }
    /* 192 bit keys */
    file << "\n\n=========================\n\nKEYSIZE=192\n";
    /* the starting key and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (unsigned char &i: ptbuf)
        i = 0;
    cipherInit(&decipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_DECRYPT, 192, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 48; k++)
            file << akey[k];
        file << "\nCT=";
        for (unsigned char k: ptbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        for (int k = 0; k < 5000; k++) {
            blockDecrypt(&decipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
        }
        /* ptbuf contains the last CT, and ctbuf has the prior... */
        file << "\nPT=";
        for (unsigned char k: ptbuf) {
            file << tohex[k >> 4] << tohex[k & 0x0f];
        }
        /* the first 64 bits come from the end of ctbuf, and
         * the remaining 128 bits from ptbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 8; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ctbuf[k + 8] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ctbuf[k + 8] & 0x0f)];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k + 16] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 16]))] ^ (
                                         ptbuf[k] >> 4)];
            akey[2 * k + 17] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 17]))] ^ (
                                         ptbuf[k] & 0x0f)];
        }
    }
    /* 256 bit keys */
    file << "\n\n=========================\n\nKEYSIZE=256\n";
    /* the starting key and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (unsigned char &i: ptbuf)
        i = 0;
    cipherInit(&decipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_DECRYPT, 256, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 64; k++)
            file << akey[k];
        file << "\nCT=";
        for (unsigned char k: ptbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        for (int k = 0; k < 5000; k++) {
            blockDecrypt(&decipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
        }
        /* ptbuf contains the last CT, and ctbuf has the prior... */
        file << "\nPT=";
        for (unsigned char k: ptbuf) {
            file << tohex[k >> 4] << tohex[k & 0x0f];
        }
        /* the first 128 bits come from ctbuf, and
         * the remaining 128 bits from ptbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ctbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ctbuf[k] & 0x0f)];
            akey[2 * k + 32] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 32]))] ^ (
                                         ptbuf[k] >> 4)];
            akey[2 * k + 33] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 33]))] ^ (
                                         ptbuf[k] & 0x0f)];
        }
    }
    file << "\n==========\n";
    file.close();
}

/**
 *  The function mct_cbc_encrypt performs Monte Carlo Tests for the CBC (Cipher Block Chaining)
 * @param ctbuf
 * @param encipher
 * @param keyin
 */
void mct_cbc_encrypt(BYTE ctbuf[16], cipherInstance &encipher, keyInstance &keyin) {
    //mct setup
    extern BYTE hex[];
    BYTE ivbuf[16];

    //file setup
    BYTE ptbuf[16];
    char akey[MAX_KEY_SIZE + 1];
    char tohex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    ofstream file("cbc_e_m.txt");
    file << "=========================\n\n";
    file << "FILENAME:  \"cbc_e_m.txt\"\n\n";
    file << "Cipher Block Chaining (CBC) Mode - ENCRYPTION\n";
    file << "Monte Carlo Test\n\n";
    file << "Algorithm Name: Mars\n";
    file << "Principle Submitter: IBM\n";

    /* 128 bit keys */
    file << "\n\n==========\n\nKEYSIZE=128\n";
    /* the starting key, IV, and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (int i = 0; i < 16; i++) {
        ptbuf[i] = 0;
        ivbuf[i] = 0;
    }
    /* we will do CBC manually */
    cipherInit(&encipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 128, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 32; k++)
            file << akey[k];
        file << "\nIV=";
        for (unsigned char k: ivbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        file << "\nPT=";
        for (unsigned char k: ptbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        for (int k = 0; k < 10000; k++) {
            for (int j = 0; j < 16; j++)
                ptbuf[j] ^= ivbuf[j];
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            for (int j = 0; j < 16; j++) {
                ptbuf[j] = ivbuf[j];
                ivbuf[j] = ctbuf[j];
            }
        }
        file << "\nCT=";
        for (int k = 0; k < 16; k++) {
            file << tohex[ctbuf[k] >> 4] << tohex[ctbuf[k] & 0x0f];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ctbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ctbuf[k] & 0x0f)];
        }
    }
    /* 192 bit keys */
    file << "\n\n==========\n\nKEYSIZE=192\n";
    /* the starting key, IV, and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (int i = 0; i < 16; i++) {
        ptbuf[i] = 0;
        ivbuf[i] = 0;
    }
    /* we will do CBC manually */
    cipherInit(&encipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 192, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 48; k++)
            file << akey[k];
        file << "\nIV=";
        for (unsigned char k: ivbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        file << "\nPT=";
        for (unsigned char k: ptbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        for (int k = 0; k < 10000; k++) {
            for (int j = 0; j < 16; j++)
                ptbuf[j] ^= ivbuf[j];
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            for (int j = 0; j < 16; j++) {
                ptbuf[j] = ivbuf[j];
                ivbuf[j] = ctbuf[j];
            }
        }
        file << "\nCT=";
        for (int k = 0; k < 16; k++) {
            file << tohex[ctbuf[k] >> 4] << tohex[ctbuf[k] & 0x0f];
        }
        /* the first 64 bits come from the end of ivbuf, and
         * the remaining 128 bits from ctbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 8; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ptbuf[k + 8] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ptbuf[k + 8] & 0x0f)];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k + 16] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 16]))] ^ (
                                         ctbuf[k] >> 4)];
            akey[2 * k + 17] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 17]))] ^ (
                                         ctbuf[k] & 0x0f)];
        }
    }
    /* 256 bit keys */
    file << "\n\n==========\n\nKEYSIZE=256\n";
    /* the starting key, IV, and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (int i = 0; i < 16; i++) {
        ptbuf[i] = 0;
        ivbuf[i] = 0;
    }
    /* we will do CBC manually */
    cipherInit(&encipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 256, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 64; k++)
            file << akey[k];
        file << "\nIV=";
        for (unsigned char k: ivbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        file << "\nPT=";
        for (unsigned char k: ptbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        for (int k = 0; k < 10000; k++) {
            for (int j = 0; j < 16; j++)
                ptbuf[j] ^= ivbuf[j];
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            for (int j = 0; j < 16; j++) {
                ptbuf[j] = ivbuf[j];
                ivbuf[j] = ctbuf[j];
            }
        }
        file << "\nCT=";
        for (int k = 0; k < 16; k++) {
            file << tohex[ctbuf[k] >> 4] << tohex[ctbuf[k] & 0x0f];
        }
        /* the first 128 bits come from ctbuf, and
         * the remaining 128 bits from ptbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ptbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ptbuf[k] & 0x0f)];
            akey[2 * k + 32] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 32]))] ^ (
                                         ctbuf[k] >> 4)];
            akey[2 * k + 33] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 33]))] ^ (
                                         ctbuf[k] & 0x0f)];
        }
    }
    file << "\n==========\n";
    file.close();
}

/**
 *  The function mct_cbc_decrypt performs Monte Carlo Tests for the CBC (Cipher Block Chaining)
 * @param ctbuf
 * @param decipher
 * @param encipher
 * @param keyin
 */
void mct_cbc_decrypt(BYTE ctbuf[16], cipherInstance &decipher, cipherInstance &encipher, keyInstance &keyin) {
    //mct setup
    extern BYTE hex[];
    BYTE ivbuf[16];

    //file setup

    BYTE ptbuf[16];
    char akey[MAX_KEY_SIZE + 1];
    char tohex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };


    ofstream file("cbc_d_m.txt");
    file << "=========================\n\n";
    file << "FILENAME:  \"cbc_d_m.txt\"\n\n";
    file << "Cipher Block Chaining (CBC) Mode - DECRYPTION\n";
    file << "Monte Carlo Test\n\n";
    file << "Algorithm Name: Mars\n";
    file << "Principle Submitter: IBM\n";

    /* 128 bit keys */
    file << "\n\n==========\n\nKEYSIZE=128\n";
    /* the starting key, IV, and CT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (int i = 0; i < 16; i++) {
        ctbuf[i] = 0;
        ivbuf[i] = 0;
    }
    /* we will do CBC manually */
    cipherInit(&decipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_DECRYPT, 128, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 32; k++)
            file << akey[k];
        file << "\nIV=";
        for (unsigned char k: ivbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        file << "\nCT=";
        for (int k = 0; k < 16; k++)
            file << tohex[ctbuf[k] >> 4] << tohex[ctbuf[k] & 0x0f];
        for (int k = 0; k < 10000; k++) {
            blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
            for (int j = 0; j < 16; j++)
                ptbuf[j] ^= ivbuf[j];
            for (int j = 0; j < 16; j++) {
                ivbuf[j] = ctbuf[j];
                ctbuf[j] = ptbuf[j];
            }
        }
        file << "\nPT=";
        for (unsigned char k: ptbuf) {
            file << tohex[k >> 4] << tohex[k & 0x0f];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ptbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ptbuf[k] & 0x0f)];
        }
    }
    /* 192 bit keys */
    file << "\n\n==========\n\nKEYSIZE=192\n";
    /* the starting key, IV, and CT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (int i = 0; i < 16; i++) {
        ctbuf[i] = 0;
        ivbuf[i] = 0;
    }
    /* we will do CBC manually */
    cipherInit(&encipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 192, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 48; k++)
            file << akey[k];
        file << "\nIV=";
        for (unsigned char k: ivbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        file << "\nCT=";
        for (int k = 0; k < 16; k++)
            file << tohex[ctbuf[k] >> 4] << tohex[ctbuf[k] & 0x0f];
        for (int k = 0; k < 10000; k++) {
            blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
            for (int j = 0; j < 16; j++)
                ptbuf[j] ^= ivbuf[j];
            for (int j = 0; j < 16; j++) {
                ivbuf[j] = ctbuf[j];
                ctbuf[j] = ptbuf[j];
            }
        }
        file << "\nPT=";
        for (unsigned char k: ptbuf) {
            file << tohex[k >> 4] << tohex[k & 0x0f];
        }
        /* the first 64 bits come from the end of ivbuf, and
         * the remaining 128 bits from ctbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 8; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ivbuf[k + 8] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ivbuf[k + 8] & 0x0f)];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k + 16] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 16]))] ^ (
                                         ptbuf[k] >> 4)];
            akey[2 * k + 17] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 17]))] ^ (
                                         ptbuf[k] & 0x0f)];
        }
    }
    /* 256 bit keys */
    file << "\n\n==========\n\nKEYSIZE=256\n";
    /* the starting key, IV, and PT are all zeros */
    for (int i = 0; i < 64; i++)
        akey[i] = '0';
    akey[64] = '\0';
    for (int i = 0; i < 16; i++) {
        ctbuf[i] = 0;
        ivbuf[i] = 0;
    }
    /* we will do CBC manually */
    cipherInit(&encipher,MODE_ECB, nullptr);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 256, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 64; k++)
            file << akey[k];
        file << "\nIV=";
        for (unsigned char k: ivbuf)
            file << tohex[k >> 4] << tohex[k & 0x0f];
        file << "\nCT=";
        for (int k = 0; k < 16; k++)
            file << tohex[ctbuf[k] >> 4] << tohex[ctbuf[k] & 0x0f];
        for (int k = 0; k < 10000; k++) {
            blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
            for (int j = 0; j < 16; j++)
                ptbuf[j] ^= ivbuf[j];
            for (int j = 0; j < 16; j++) {
                ivbuf[j] = ctbuf[j];
                ctbuf[j] = ptbuf[j];
            }
        }
        file << "\nPT=";
        for (unsigned char k: ptbuf) {
            file << tohex[k >> 4] << tohex[k & 0x0f];
        }
        /* the first 128 bits come from ctbuf, and
         * the remaining 128 bits from ptbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k]))] ^ (ivbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 1]))] ^ (
                                        ivbuf[k] & 0x0f)];
            akey[2 * k + 32] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 32]))] ^ (
                                         ptbuf[k] >> 4)];
            akey[2 * k + 33] = tohex[hex[static_cast<int>(static_cast<unsigned char>(akey[2 * k + 33]))] ^ (
                                         ptbuf[k] & 0x0f)];
        }
    }
    file << "\n==========\n";
    file.close();
}


int main() {
    // creates instances of the key and cipher
    keyInstance keyin;
    cipherInstance encipher, decipher;
    // creates arrays of WORDs, BYTEs, and chars storing the plaintext, ciphertext, and key
    WORD pt_in[NUM_DATA], ct[NUM_DATA], pt_out[NUM_DATA];
    WORD key[EKEY_WORDS];
    // array of chars storing additional key words
    WORD e[EKEY_WORDS];
    // array of BYTEs storing the ciphertext and output buffer
    BYTE ctbuf[32], outbuf[32];
    // variables for timing tests to measure the time it takes to encrypt and decrypt blocks
    int i;

    cout << "MARS Test Program\n";
    /* do simple CBC encrypt/decrypt test for the high level stuff first */
    char keyMaterial[] = "000102030405060708090a0b0c0d0e0f";
    makeKey(&keyin, DIR_ENCRYPT, 128, keyMaterial);
    char iv[] = "00000000000000000000000000000000";
    cipherInit(&encipher, MODE_CBC, iv);
    cipherInit(&decipher, MODE_CBC, iv);
    // Make a copy of the string literal
    char buffer[] = "This is a two block test of CBC";

    // Encrypt the copied string
    blockEncrypt(&encipher, &keyin,
                 reinterpret_cast<BYTE *>(buffer), 256, ctbuf);

    // Decrypt the ciphertext
    blockDecrypt(&decipher, &keyin, ctbuf, 256, outbuf);

    // Print the decrypted message
    cout << "\nHigh level output test: \n" << reinterpret_cast<char *>(outbuf) << "\n";

    /* try the CFB-1 mode */
    makeKey(&keyin,DIR_ENCRYPT, 128, keyMaterial);
    cipherInit(&encipher,MODE_CFB1, iv);
    cipherInit(&decipher,MODE_CFB1, iv);
    for (i = 0; i < 8; i++) {
        outbuf[0] = (i & 1);
        blockEncrypt(&encipher, &keyin, outbuf, 1, ctbuf);
        blockDecrypt(&decipher, &keyin, ctbuf, 1, outbuf);
        cout << " CFB-1 bit " << i << " bitin " << (i & 1) << " ctbit " << static_cast<int>(ctbuf[0]) << " bitout " <<
                static_cast<int>(outbuf[0]) << endl;
    }
    cout << "\n";

    /* do simple encrypt/decrypt test for the low level stuff */
    cout << "Low level block tests:" << endl;
    for (i = 0; i < 4; i++) {
        pt_in[i] = 0x01020304;
        key[i] = 0x01020304;
    }
    (void) mars_setup(4, key, e);
    mars_encrypt(pt_in, ct, e);
    mars_decrypt(ct, pt_out, e);
    printf(" in     %.8lX %.8lX %.8lX %.8lX\n",
           pt_in[0], pt_in[1], pt_in[2], pt_in[3]);
    printf(" cipher %.8lX %.8lX %.8lX %.8lX\n",
           ct[0], ct[1], ct[2], ct[3]);
    printf(" out    %.8lX %.8lX %.8lX %.8lX\n",
           pt_out[0], pt_out[1], pt_out[2], pt_out[3]);
    if (pt_in[0] != pt_out[0] || pt_in[1] != pt_out[1] ||
        pt_in[2] != pt_out[2] || pt_in[3] != pt_out[3])
        cout << "Decryption Error!" << endl;
    fflush(stdout);

    /* Do low level timing tests */
    cout << "Low level block timing tests:" << endl;
    clock_t clock1 = clock();
    for (i = 1; i < 40000; i++) {
        (void) mars_setup(4, key, e);
        key[0]++;
    }
    clock_t clock2 = clock();
    float ttime1 = static_cast<float>(clock2 - clock1) / CLOCKS_PER_SEC;
    cout << "Time for 40K 128 bit setups: " << ttime1 << endl;
    cout << " " << (5.12 / ttime1) << " Mbit/sec" << endl;


    (void) mars_setup(4, key, e);
    clock1 = clock();
    for (i = 1; i < 400000; i++)
        mars_encrypt(pt_in, ct, e);
    clock2 = clock();
    ttime1 = static_cast<float>(clock2 - clock1) / CLOCKS_PER_SEC;
    cout << "Time for encrypting 400K 128 bit blocks: " << ttime1 << endl;
    cout << " " << (51.2 / ttime1) << " Mbit/sec" << endl;

    clock1 = clock();
    for (i = 1; i < 400000; i++)
        mars_decrypt(pt_in, ct, e);
    clock2 = clock();
    ttime1 = static_cast<float>(clock2 - clock1) / CLOCKS_PER_SEC;
    cout << "Time for decrypting 400K 128 bit blocks: " << ttime1 << endl;
    cout << " " << (51.2 / ttime1) << " Mbit/sec" << endl;


    cout << "Other tests" << endl;

    cout << "IVT ECB Test" << endl;
    ivt_ecb(ctbuf, outbuf, decipher, encipher, keyin);

    cout << "Variable key KAT Test" << endl;
    key_kat(ctbuf, outbuf, decipher, encipher, keyin);

    cout << "Variable txt KAT Test" << endl;
    text_kat_var(ctbuf, outbuf, decipher, encipher, keyin);

    cout << "MCT ECB Decryption Test" << endl;
    mct_ecb_decrypt(ctbuf, decipher, encipher, keyin);

    cout << "MCT CBC Encryption Test" << endl;
    mct_cbc_encrypt(ctbuf, encipher, keyin);

    cout << "MCT CBC Decryption Test" << endl;
    mct_cbc_decrypt(ctbuf, decipher, encipher, keyin);


    return (0);
}
