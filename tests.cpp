#include "aes.h"
#include <ctime>
#include <iomanip>
#include <fstream>
#include <iostream>
using namespace std;
/*************************************************************************
 *
 *   test main() for the high and low level routines
 *
 ************************************************************************/



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

    cout<<"MARS Test Program\n";
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

    return (0);
}
