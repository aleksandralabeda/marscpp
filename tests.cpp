#include "aes.h"
#include <ctime>
#include <iomanip>
#include <fstream>
#include <iostream>
using namespace std;


void mct_cbc_decrypt(BYTE ctbuf[16], cipherInstance &decipher, cipherInstance &encipher, keyInstance &keyin) {
//mct setup
    extern BYTE hex[];
    BYTE ivbuf[16];

//file setup
    FILE *fp;
    BYTE ptbuf[16];
    char akey[MAX_KEY_SIZE + 1];
    char tohex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    int j, k;


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
    cipherInit(&decipher,MODE_ECB,NULL);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_DECRYPT, 128, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 32; k++)
            file << akey[k];
        file << "\nIV=";
        for (int k = 0; k < 16; k++)
            file << tohex[ivbuf[k] >> 4] << tohex[ivbuf[k] & 0x0f];
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
        for (int k = 0; k < 16; k++) {
            file << tohex[ptbuf[k] >> 4] << tohex[ptbuf[k] & 0x0f];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[(int) akey[2 * k]] ^ (ptbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[(int) hex[(int) akey[2 * k + 1]] ^ (ptbuf[k] & 0x0f)];
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
    cipherInit(&encipher,MODE_ECB,NULL);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 192, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 48; k++)
            file << akey[k];
        file << "\nIV=";
        for (int k = 0; k < 16; k++)
            file << tohex[ivbuf[k] >> 4] << tohex[ivbuf[k] & 0x0f];
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
        for (int k = 0; k < 16; k++) {
            file << tohex[ptbuf[k] >> 4] << tohex[ptbuf[k] & 0x0f];
        }
        /* the first 64 bits come from the end of ivbuf, and
         * the remaining 128 bits from ctbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 8; k++) {
            akey[2 * k] = tohex[hex[(int) akey[2 * k]] ^ (ivbuf[k + 8] >> 4)];
            akey[2 * k + 1] = tohex[hex[(int) akey[2 * k + 1]] ^ (ivbuf[k + 8] & 0x0f)];
        }
        for (int k = 0; k < 16; k++) {
            akey[2 * k + 16] = tohex[hex[(int) akey[2 * k + 16]] ^ (ptbuf[k] >> 4)];
            akey[2 * k + 17] = tohex[(int) hex[(int) akey[2 * k + 17]] ^ (ptbuf[k] & 0x0f)];
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
    cipherInit(&encipher,MODE_ECB,NULL);
    for (int i = 0; i < 400; i++) {
        makeKey(&keyin,DIR_ENCRYPT, 256, akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for (int k = 0; k < 64; k++)
            file << akey[k];
        file << "\nIV=";
        for (int k = 0; k < 16; k++)
            file << tohex[ivbuf[k] >> 4] << tohex[ivbuf[k] & 0x0f];
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
        for (int k = 0; k < 16; k++) {
            file << tohex[ptbuf[k] >> 4] << tohex[ptbuf[k] & 0x0f];
        }
        /* the first 128 bits come from ctbuf, and
         * the remaining 128 bits from ptbuf (CT9999, and CT9998)
         */
        for (int k = 0; k < 16; k++) {
            akey[2 * k] = tohex[hex[(int) akey[2 * k]] ^ (ivbuf[k] >> 4)];
            akey[2 * k + 1] = tohex[hex[(int) akey[2 * k + 1]] ^ (ivbuf[k] & 0x0f)];
            akey[2 * k + 32] = tohex[hex[(int) akey[2 * k + 32]] ^ (ptbuf[k] >> 4)];
            akey[2 * k + 33] = tohex[(int) hex[(int) akey[2 * k + 33]] ^ (ptbuf[k] & 0x0f)];
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
    printf("\nHigh level output test: \n %s\n", reinterpret_cast<char *>(outbuf));


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


    cout << "Low level tests" << endl;

    cout << "MCT CBC Decryption Test" << endl;
    mct_cbc_decrypt(ctbuf, decipher, encipher, keyin);


    return (0);
}
