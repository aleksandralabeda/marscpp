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

#ifdef IVT
#ifndef TESTS
#define TESTS
#endif
#endif
#ifdef KAT
#ifndef TESTS
#define TESTS
#endif
#endif
#ifdef MCT
#ifndef TESTS
#define TESTS
#endif
#endif

int main() {
    keyInstance keyin;
    cipherInstance encipher, decipher;
    WORD pt_in[NUM_DATA], ct[NUM_DATA], pt_out[NUM_DATA];
    WORD key[EKEY_WORDS];
    WORD e[EKEY_WORDS];
    BYTE ctbuf[32], outbuf[32];
    clock_t clock1, clock2;
    float ttime1;
    int i;
#   ifdef DIEHARD
        int fd;
#   endif
#   ifdef IVT
        extern int ivt_debug;
        extern FILE *ivt_fp;
        extern int ivt_l;
#   endif
#ifdef MCT
        extern BYTE hex[];
        BYTE ivbuf[16];
#endif
#ifdef KAT
        WORD S[16] = {0xf20b4862, 0xcd79bde4, 0x498f7a5b, 0xcfc31f4c,
                      0x354d61f3, 0x2e31fa47, 0x8c18da7f, 0xe14e831d,
                      0x5de9d8d6, 0x68843750, 0xa2e71b63, 0xeff8e372,
                      0x8792349d, 0x8a58369a, 0x2e9382ba, 0xa72b988f};
#endif
#ifdef TESTS
    fstream file;
    BYTE ptbuf[16];
    char akey[MAX_KEY_SIZE+1];
    char tohex[16] = { '0','1','2','3','4','5','6','7','8',
                       '9','A','B','C','D','E','F' };
    int j,k;
#endif /* TESTS */

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
    clock1 = clock();
    for (i = 1; i < 40000; i++) {
        (void) mars_setup(4, key, e);
        key[0]++;
    }
    clock2 = clock();
    ttime1 = static_cast<double>(clock2 - clock1) / CLOCKS_PER_SEC;
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

#ifdef DIEHARD
    /* write file for diehard randomness stress tests */
    ofstream file("mars.dat", ios::binary);
    mars_setup(4, key, e);
    for (int i = 0; i < 1024*1024; i++) {
        pt_in[0] = i;
        mars_encrypt(pt_in, ct, e);
        file.write(reinterpret_cast<char*>(ct), 16);
    }
    file.close();
#endif /* DIEHARD */
    ////////////////////////////////////////////////
#ifdef IVT
    /*************************************************************************
     *
     * Intermediate Value Test -> ecb_ivt.txt
     *
     ************************************************************************/
  // Intermediate Value Test -> ecb_ivt.txt
ofstream file("ecb_ivt.txt");
ivt_l = 0;
ivt_debug=1;
file << "=========================\n\n";
file << "FILENAME:  \"ecb_ivt.txt\"\n\n";
file << "Electronic Codebook (ECB) Mode\n";
file << "Intermediate Values Tests\n\n";
file << "Algorithm Name: Mars\n";
file << "Principle Submitter: IBM\n";

// the input plaintext and key are all zeros
for(int i=0;i<16;i++)
    ptbuf[i] = 0;

// 128 bit keys
for(int i=0;i<32;i++)
    akey[i] = '0';
akey[32] = '\0';
file << "\n\n==========\n\nEncryption: KEYSIZE=128\n\n";
file << "KEY=" << akey << "\n";
file << "PT=00000000000000000000000000000000\n";
makeKey(&keyin,DIR_ENCRYPT,128,akey);
cipherInit(&encipher,MODE_ECB,NULL);
cipherInit(&decipher,MODE_ECB,NULL);
blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
file << "CT=";
for(int k=0;k<16;k++)
    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
file << "\n\n==========\n\nDecryption: KEYSIZE=128\n\n";
file << "KEY=" << akey << "\n";
file << "CT=";
for(int k=0;k<16;k++)
    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
ivt_l = 0;
file << "\n";
blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
file << "PT=";
for(int k=0;k<16;k++)
    file << hex << setw(2) << setfill('0') << static_cast<int>(outbuf[k]);

// 192 bit keys
for(int i=0;i<48;i++)
    akey[i] = '0';
akey[48] = '\0';
file << "\n\n==========\n\nEncryption: KEYSIZE=192\n\n";
file << "KEY=" << akey << "\n";
file << "PT=00000000000000000000000000000000\n";
makeKey(&keyin,DIR_ENCRYPT,192,akey);
cipherInit(&encipher,MODE_ECB,NULL);
cipherInit(&decipher,MODE_ECB,NULL);
ivt_l = 0;
blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
file << "CT=";
for(int k=0;k<16;k++)
    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
file << "\n\n==========\n\nDecryption: KEYSIZE=192\n\n";
file << "KEY=" << akey << "\n";
file << "CT=";
for(int k=0;k<16;k++)
    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
ivt_l = 0;
file << "\n";
blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
file << "PT=";
for(int k=0;k<16;k++)
    file << hex << setw(2) << setfill('0') << static_cast<int>(outbuf[k]);

// 256 bit keys
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
file << "\n\n==========\n\nEncryption: KEYSIZE=256\n\n";
file << "KEY=" << akey << "\n";
file << "PT=00000000000000000000000000000000\n";
makeKey(&keyin,DIR_ENCRYPT,256,akey);
cipherInit(&encipher,MODE_ECB,NULL);
cipherInit(&decipher,MODE_ECB,NULL);
ivt_l = 0;
blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
file << "CT=";
for(int k=0;k<16;k++)
    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
file << "\n\n==========\n\nDecryption: KEYSIZE=256\n\n";
file << "KEY=" << akey << "\n";
file << "CT=";
for(int k=0;k<16;k++)
    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
ivt_l = 0;
file << "\n";
blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
file << "PT=";
for(int k=0;k<16;k++)
    file << hex << setw(2) << setfill('0') << static_cast<int>(outbuf[k]);
file << "\n";
file.close();
ivt_debug=0;
j = 0;  // make Wall happy
#endif /* IVT */

#ifdef KAT
    /*************************************************************************
     *
     * Variable Key KAT -> ecb_vk.txt
     *
     ************************************************************************/
/////////////////////////////////////////////////////////////////////////////////////////////
// 128 bit keys
ofstream file("ecb_vk.txt");
file << "=========================\n\n";
file << "FILENAME:  \"ecb_vk.txt\"\n\n";
file << "Electronic Codebook (ECB) Mode\n";
file << "Variable Key Known Answer Tests\n\n";
file << "Algorithm Name: Mars\n";
file << "Principle Submitter: IBM\n";
// the input plaintext is all zeros
for(int i = 0; i < 16; i++)
    ptbuf[i] = 0;

    // 128 bit keys
akey[32] = '\0';
file << "\n\n==========\n\nKEYSIZE=128\n\n";
file << "PT=00000000000000000000000000000000\n";

for(int i = 0; i < 32; i++) {
    for(int j = 3; j >= 0; j--){
        for (int k = 0; k < 32; k++)
            akey[k] = '0';
        akey[i] = '0' + (1<<j);
        makeKey(&keyin,DIR_ENCRYPT,128,akey);
        cipherInit(&encipher,MODE_ECB,NULL);
        cipherInit(&decipher,MODE_ECB,NULL);
        blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
        blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
        file << "\n\nI=" << i*4+4-j << "\n";
        file << "KEY=" << akey << "\n";
        file << "CT=";
        for(int k = 0; k < 16; k++){
            if(outbuf[k] != 0)
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

for(int i = 0; i < 48; i++) {
    for(int j = 3; j >= 0; j--){
        for (int k = 0; k < 48; k++)
            akey[k] = '0';
        akey[i] = '0' + (1<<j);
        makeKey(&keyin,DIR_ENCRYPT,192,akey);
        cipherInit(&encipher,MODE_ECB,NULL);
        cipherInit(&decipher,MODE_ECB,NULL);
        blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
        blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
        file << "\n\nI=" << i*4+4-j << "\n";
        file << "KEY=" << akey << "\n";
        file << "CT=";
        for(int k = 0; k < 16; k++){
            if(outbuf[k] != 0)
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

    for(int i = 0; i < 64; i++) {
        for(int j = 3; j >= 0; j--){
            for (int k = 0; k < 64; k++)
                akey[k] = '0';
            akey[i] = '0' + (1<<j);
            makeKey(&keyin,DIR_ENCRYPT,256,akey);
            cipherInit(&encipher,MODE_ECB,NULL);
            cipherInit(&decipher,MODE_ECB,NULL);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i*4+4-j << "\n";
            file << "KEY=" << akey << "\n";
            file << "CT=";
            for(int k = 0; k < 16; k++){
                if(outbuf[k] != 0)
                    file << "*decryption error*\n";
                else
                    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
            }
            file << "\n";
        }
    }
    file << "\n==========\n";
    file.close();
/////////////////////////////////////////////////////////////////////////////////////////////////
    /*************************************************************************
     *
     * Variable Text KAT -> ecb_vt.txt
     *
     ************************************************************************/
    ofstream file("ecb_vt.txt");
    file << "=========================\n\n";
    file << "FILENAME:  \"ecb_vt.txt\"\n\n";
    file << "Electronic Codebook (ECB) Mode\n";
    file << "Variable Text Known Answer Tests\n\n";
    file << "Algorithm Name: Mars\n";
    file << "Principle Submitter: IBM\n";
    /* the input key is all zeros */
    for(int i=0;i<64;i++)
        akey[i] = '0';
    akey[64] = '\0';
    /* 128 bit keys */
    file << "\n\n==========\n\nKEYSIZE=128\n\n";
    file << "KEY=00000000000000000000000000000000\n";
    for(int i=0;i<16;i++) {
        for(int j=7;j>=0;j--){
            for (int k=0;k<16;k++)
                ptbuf[k] = 0;
            ptbuf[i] = (1<<j);
            makeKey(&keyin,DIR_ENCRYPT,128,akey);
            cipherInit(&encipher,MODE_ECB,NULL);
            cipherInit(&decipher,MODE_ECB,NULL);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i*8+8-j << "\n";
            file << "PT=";
            for(int k=0;k<16;k++)
                file << hex << setw(2) << setfill('0') << static_cast<int>(ptbuf[k]);
            file << "\nCT=";
            for(int k=0;k<16;k++){
                if(outbuf[k] != ptbuf[k])
                    file << "*decryption error*\n";
                else
                    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
            }
        }
    }
    /* 192 bit keys */
    file << "\n\n==========\n\nKEYSIZE=192\n\n";
    file << "KEY=000000000000000000000000000000000000000000000000\n";
    for(int i=0;i<16;i++) {
        for(int j=7;j>=0;j--){
            for (int k=0;k<16;k++)
                ptbuf[k] = 0;
            ptbuf[i] = (1<<j);
            makeKey(&keyin,DIR_ENCRYPT,192,akey);
            cipherInit(&encipher,MODE_ECB,NULL);
            cipherInit(&decipher,MODE_ECB,NULL);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i*8+8-j << "\n";
            file << "PT=";
            for(int k=0;k<16;k++)
                file << hex << setw(2) << setfill('0') << static_cast<int>(ptbuf[k]);
            file << "\nCT=";
            for(int k=0;k<16;k++){
                if(outbuf[k] != ptbuf[k])
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
    for(int i=0;i<16;i++) {
        for(int j=7;j>=0;j--){
            for (int k=0;k<16;k++)
                ptbuf[k] = 0;
            ptbuf[i] = (1<<j);
            makeKey(&keyin,DIR_ENCRYPT,256,akey);
            cipherInit(&encipher,MODE_ECB,NULL);
            cipherInit(&decipher,MODE_ECB,NULL);
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockDecrypt(&decipher, &keyin, ctbuf, 128, outbuf);
            file << "\n\nI=" << i*8+8-j << "\n";
            file << "PT=";
            for(int k=0;k<16;k++)
                file << hex << setw(2) << setfill('0') << static_cast<int>(ptbuf[k]);
            file << "\nCT=";
            for(int k=0;k<16;k++){
                if(outbuf[k] != ptbuf[k])
                    file << "*decryption error*\n";
                else
                    file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
            }
        }
    }
    file << "\n==========\n";
    file.close();
//////////////////////////////////////////////////////////////////////////////////////////
Here is the C++ version of the selected code:

```cpp
/* Tables KAT -> ecb_tbl.txt
 * To test all Sbox entries, we fix the key to be zero, start
 * with some initial plaintext, and iterate, setting each
 * next plaintext to the last ciphertext output.  We instrumented
 * the sbox lookups, and found that after 40 such iterations, all
 * sboxes had been used at least once for each key length.
 */
ofstream file("ecb_tbl.txt");
file << "/*  This tests all 512 entries in the fixed Sbox  */\n\n";
file << "=========================\n\n";
file << "FILENAME:  \"ecb_tbl.txt\"\n\n";
file << "Electronic Codebook (ECB) Mode\n";
file << "Tables Known Answer Tests\n\n";
file << "Algorithm Name: Mars\n";
file << "Principle Submitter: IBM";
/* the input key is all zeros */
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';

/* 128 bit keys */
file << "\n\n==========\n\nKEYSIZE=128\n";
makeKey(&keyin,DIR_ENCRYPT,128,akey);
cipherInit(&encipher,MODE_ECB,NULL);
/* set some interesting starting text */
for(int i=0;i<16;i++)
    ptbuf[i] = 0;
for(int i=1;i<41;i++) {
    blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
    file << "\n\nI=" << i << "\n";
    file << "KEY=00000000000000000000000000000000\n";
    file << "PT=";
    for(int k=0;k<16;k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ptbuf[k]);
    file << "\nCT=";
    for(int k=0;k<16;k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
    for(int j=0;j<16;j++)
        ptbuf[j] = ctbuf[j];
}
/* 192 bit keys */
file << "\n\n==========\n\nKEYSIZE=192\n";
makeKey(&keyin,DIR_ENCRYPT,192,akey);
cipherInit(&encipher,MODE_ECB,NULL);
/* set some interesting starting text */
for(int i=0;i<16;i++)
    ptbuf[i] = 0xaa;
for(int i=1;i<41;i++) {
    blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
    file << "\n\nI=" << i << "\n";
    file << "KEY=00000000000000000000000000000000";
    file << "0000000000000000\n";
    file << "PT=";
    for(int k=0;k<16;k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ptbuf[k]);
    file << "\nCT=";
    for(int k=0;k<16;k++)
        file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
    for(int j=0;j<16;j++)
        ptbuf[j] = ctbuf[j];
}
    /* 256 bit keys */
    file << "\n\n==========\n\nKEYSIZE=256\n";
    makeKey(&keyin,DIR_ENCRYPT,256,akey);
    cipherInit(&encipher,MODE_ECB,NULL);
    /* set some interesting starting text */
    for(int i=0;i<16;i++)
        ptbuf[i] = S[i]&0xff;
    for(int i=1;i<41;i++) {
        blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
        file << "\n\nI=" << i << "\n";
        file << "KEY=00000000000000000000000000000000";
        file << "00000000000000000000000000000000\n";
        file << "PT=";
        for(int k=0;k<16;k++)
            file << hex << setw(2) << setfill('0') << static_cast<int>(ptbuf[k]);
        file << "\nCT=";
        for(int k=0;k<16;k++)
            file << hex << setw(2) << setfill('0') << static_cast<int>(ctbuf[k]);
        for(int j=0;j<16;j++)
            ptbuf[j] = ctbuf[j];
    }
    file << "\n==========\n";
    file.close();
#endif /* KAT */
    ////////////////////////////////////////////////////////////////////////////////////////
#ifdef MCT
    /*************************************************************************
     *
     * ECB Encrypt MCT -> ecb_e_m.txt
     *
     ************************************************************************/
    ofstream file("ecb_e_m.txt");
    file << "=========================\n\n";
    file << "FILENAME:  \"ecb_e_m.txt\"\n\n";
    file << "Electronic Codebook (ECB) Mode - ENCRYPTION\n";
    file << "Monte Carlo Test\n\n";
    file << "Algorithm Name: Mars\n";
    file << "Principle Submitter: IBM\n";

    /* 128 bit keys */
    file << "\n\n=========================\n\nKEYSIZE=128\n";
    /* the starting key and PT are all zeros */
    for(int i=0;i<64;i++)
        akey[i] = '0';
    akey[64] = '\0';
    for(int i=0;i<16;i++)
        ptbuf[i] = 0;
    cipherInit(&encipher,MODE_ECB,NULL);
    for(int i=0;i<400;i++) {
        makeKey(&keyin,DIR_ENCRYPT,128,akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for(int k=0;k<32;k++)
            file << akey[k];
        file << "\nPT=";
        for(int k=0;k<16;k++)
            file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
        for(int k=0;k<5000;k++){
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockEncrypt(&encipher, &keyin, ctbuf, 128, ptbuf);
        }
        file << "\nCT=";
        for(int k=0;k<16;k++){
            file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
        }
        for(int k=0;k<16;k++){
            akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ptbuf[k]>>4)];
            akey[2*k+1] = tohex[(int)hex[(int)akey[2*k+1]] ^ (ptbuf[k] & 0x0f)];
        }
    }
    /* 192 bit keys */
    file << "\n\n=========================\n\nKEYSIZE=192\n";
    /* the starting key and PT are all zeros */
    for(int i=0;i<64;i++)
        akey[i] = '0';
    akey[64] = '\0';
    for(int i=0;i<16;i++)
        ptbuf[i] = 0;
    cipherInit(&encipher,MODE_ECB,NULL);
    for(int i=0;i<400;i++) {
        makeKey(&keyin,DIR_ENCRYPT,192,akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for(int k=0;k<48;k++)
            file << akey[k];
        file << "\nPT=";
        for(int k=0;k<16;k++)
            file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
        for(int k=0;k<5000;k++){
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockEncrypt(&encipher, &keyin, ctbuf, 128, ptbuf);
        }
        /* ptbuf contains the last CT, and ctbuf has the prior... */
        file << "\nCT=";
        for(int k=0;k<16;k++){
            file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
        }
        /* the first 64 bits come from the end of ctbuf, and
         * the remaining 128 bits from ptbuf (CT9999, and CT9998)
         */
        for(int k=0;k<8;k++) {
            akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ctbuf[k+8]>>4)];
            akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ctbuf[k+8] & 0x0f)];
        }
        for(int k=0;k<16;k++){
            akey[2*k+16] = tohex[hex[(int)akey[2*k+16]]^(ptbuf[k]>>4)];
            akey[2*k+17] = tohex[(int)hex[(int)akey[2*k+17]]^(ptbuf[k]&0x0f)];
        }
    }
    /* 256 bit keys */
    file << "\n\n=========================\n\nKEYSIZE=256\n";
    /* the starting key and PT are all zeros */
    for(int i=0;i<64;i++)
        akey[i] = '0';
    akey[64] = '\0';
    for(int i=0;i<16;i++)
        ptbuf[i] = 0;
    cipherInit(&encipher,MODE_ECB,NULL);
    for(int i=0;i<400;i++) {
        makeKey(&keyin,DIR_ENCRYPT,256,akey);
        file << "\n\nI=" << i << "\n";
        file << "KEY=";
        for(int k=0;k<64;k++)
            file << akey[k];
        file << "\nPT=";
        for(int k=0;k<16;k++)
            file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
        for(int k=0;k<5000;k++){
            blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
            blockEncrypt(&encipher, &keyin, ctbuf, 128, ptbuf);
        }
        /* ptbuf contains the last CT, and ctbuf has the prior... */
        file << "\nCT=";
        for(int k=0;k<16;k++){
            file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
        }
        /* the first 128 bits come from ctbuf, and
         * the remaining 128 bits from ptbuf (CT9999, and CT9998)
         */
        for(int k=0;k<16;k++) {
            akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ctbuf[k]>>4)];
            akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ctbuf[k] & 0x0f)];
            akey[2*k+32] = tohex[hex[(int)akey[2*k+32]]^(ptbuf[k]>>4)];
            akey[2*k+33] = tohex[(int)hex[(int)akey[2*k+33]]^(ptbuf[k]&0x0f)];
        }
    }
    file << "\n==========\n";
    file.close();

/*************************************************************************
 *
 * ECB Decrypt MCT -> ecb_d_m.txt
 *
 ************************************************************************/
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
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
for(int i=0;i<16;i++)
    ptbuf[i] = 0;
cipherInit(&decipher,MODE_ECB,NULL);
for(int i=0;i<400;i++) {
    makeKey(&keyin,DIR_DECRYPT,128,akey);
    file << "\n\nI=" << i << "\n";
    file << "KEY=";
    for(int k=0;k<32;k++)
        file << akey[k];
    file << "\nCT=";
    for(int k=0;k<16;k++)
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    for(int k=0;k<5000;k++){
        blockDecrypt(&decipher, &keyin, ptbuf, 128, ctbuf);
        blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
    }
    file << "\nPT=";
    for(int k=0;k<16;k++){
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    }
    for(int k=0;k<16;k++){
        akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ptbuf[k]>>4)];
        akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ptbuf[k] & 0x0f)];
    }
}
/* 192 bit keys */
file << "\n\n=========================\n\nKEYSIZE=192\n";
/* the starting key and PT are all zeros */
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
for(int i=0;i<16;i++)
    ptbuf[i] = 0;
cipherInit(&decipher,MODE_ECB,NULL);
for(int i=0;i<400;i++) {
    makeKey(&keyin,DIR_DECRYPT,192,akey);
    file << "\n\nI=" << i << "\n";
    file << "KEY=";
    for(int k=0;k<48;k++)
        file << akey[k];
    file << "\nCT=";
    for(int k=0;k<16;k++)
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    for(int k=0;k<5000;k++){
        blockDecrypt(&decipher, &keyin, ptbuf, 128, ctbuf);
        blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
    }
    /* ptbuf contains the last CT, and ctbuf has the prior... */
    file << "\nPT=";
    for(int k=0;k<16;k++){
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    }
    /* the first 64 bits come from the end of ctbuf, and
     * the remaining 128 bits from ptbuf (CT9999, and CT9998)
     */
    for(int k=0;k<8;k++) {
        akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ctbuf[k+8]>>4)];
        akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ctbuf[k+8] & 0x0f)];
    }
    for(int k=0;k<16;k++){
        akey[2*k+16] = tohex[hex[(int)akey[2*k+16]]^(ptbuf[k]>>4)];
        akey[2*k+17] = tohex[hex[(int)akey[2*k+17]]^(ptbuf[k]&0x0f)];
    }
}
/* 256 bit keys */
file << "\n\n=========================\n\nKEYSIZE=256\n";
/* the starting key and PT are all zeros */
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
for(int i=0;i<16;i++)
    ptbuf[i] = 0;
cipherInit(&decipher,MODE_ECB,NULL);
for(int i=0;i<400;i++) {
    makeKey(&keyin,DIR_DECRYPT,256,akey);
    file << "\n\nI=" << i << "\n";
    file << "KEY=";
    for(int k=0;k<64;k++)
        file << akey[k];
    file << "\nCT=";
    for(int k=0;k<16;k++)
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    for(int k=0;k<5000;k++){
        blockDecrypt(&decipher, &keyin, ptbuf, 128, ctbuf);
        blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
    }
    /* ptbuf contains the last CT, and ctbuf has the prior... */
    file << "\nPT=";
    for(int k=0;k<16;k++){
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    }
    /* the first 128 bits come from ctbuf, and
     * the remaining 128 bits from ptbuf (CT9999, and CT9998)
     */
    for(int k=0;k<16;k++) {
        akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ctbuf[k]>>4)];
        akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ctbuf[k] & 0x0f)];
        akey[2*k+32] = tohex[hex[(int)akey[2*k+32]]^(ptbuf[k]>>4)];
        akey[2*k+33] = tohex[hex[(int)akey[2*k+33]]^(ptbuf[k]&0x0f)];
    }
}
file << "\n==========\n";
file.close();
/*************************************************************************
 *
 * CBC Encrypt MCT -> cbc_e_m.txt
 *
 ************************************************************************/
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
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
for(int i=0;i<16;i++){
    ptbuf[i] = 0;
    ivbuf[i] = 0;
}
/* we will do CBC manually */
cipherInit(&encipher,MODE_ECB,NULL);
for(int i=0;i<400;i++) {
    makeKey(&keyin,DIR_ENCRYPT,128,akey);
    file << "\n\nI=" << i << "\n";
    file << "KEY=";
    for(int k=0;k<32;k++)
        file << akey[k];
    file << "\nIV=";
    for(int k=0;k<16;k++)
        file << tohex[ivbuf[k]>>4] << tohex[ivbuf[k]&0x0f];
    file << "\nPT=";
    for(int k=0;k<16;k++)
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    for(int k=0;k<10000;k++){
        for(int j=0;j<16;j++)
            ptbuf[j] ^= ivbuf[j];
        blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
        for(int j=0;j<16;j++){
            ptbuf[j] = ivbuf[j];
            ivbuf[j] = ctbuf[j];
        }
    }
    file << "\nCT=";
    for(int k=0;k<16;k++){
        file << tohex[ctbuf[k]>>4] << tohex[ctbuf[k]&0x0f];
    }
    for(int k=0;k<16;k++){
        akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ctbuf[k]>>4)];
        akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ctbuf[k] & 0x0f)];
    }
}
/* 192 bit keys */
file << "\n\n==========\n\nKEYSIZE=192\n";
/* the starting key, IV, and PT are all zeros */
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
for(int i=0;i<16;i++){
    ptbuf[i] = 0;
    ivbuf[i] = 0;
}
/* we will do CBC manually */
cipherInit(&encipher,MODE_ECB,NULL);
for(int i=0;i<400;i++) {
    makeKey(&keyin,DIR_ENCRYPT,192,akey);
    file << "\n\nI=" << i << "\n";
    file << "KEY=";
    for(int k=0;k<48;k++)
        file << akey[k];
    file << "\nIV=";
    for(int k=0;k<16;k++)
        file << tohex[ivbuf[k]>>4] << tohex[ivbuf[k]&0x0f];
    file << "\nPT=";
    for(int k=0;k<16;k++)
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    for(int k=0;k<10000;k++){
        for(int j=0;j<16;j++)
            ptbuf[j] ^= ivbuf[j];
        blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
        for(int j=0;j<16;j++){
            ptbuf[j] = ivbuf[j];
            ivbuf[j] = ctbuf[j];
        }
    }
    file << "\nCT=";
    for(int k=0;k<16;k++){
        file << tohex[ctbuf[k]>>4] << tohex[ctbuf[k]&0x0f];
    }
    /* the first 64 bits come from the end of ivbuf, and
     * the remaining 128 bits from ctbuf (CT9999, and CT9998)
     */
    for(int k=0;k<8;k++) {
        akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ptbuf[k+8]>>4)];
        akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ptbuf[k+8] & 0x0f)];
    }
    for(int k=0;k<16;k++){
        akey[2*k+16] = tohex[hex[(int)akey[2*k+16]]^(ctbuf[k]>>4)];
        akey[2*k+17] = tohex[(int)hex[(int)akey[2*k+17]]^(ctbuf[k]&0x0f)];
    }
}
/* 256 bit keys */
file << "\n\n==========\n\nKEYSIZE=256\n";
/* the starting key, IV, and PT are all zeros */
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
for(int i=0;i<16;i++){
    ptbuf[i] = 0;
    ivbuf[i] = 0;
}
/* we will do CBC manually */
cipherInit(&encipher,MODE_ECB,NULL);
for(int i=0;i<400;i++) {
    makeKey(&keyin,DIR_ENCRYPT,256,akey);
    file << "\n\nI=" << i << "\n";
    file << "KEY=";
    for(int k=0;k<64;k++)
        file << akey[k];
    file << "\nIV=";
    for(int k=0;k<16;k++)
        file << tohex[ivbuf[k]>>4] << tohex[ivbuf[k]&0x0f];
    file << "\nPT=";
    for(int k=0;k<16;k++)
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    for(int k=0;k<10000;k++){
        for(int j=0;j<16;j++)
            ptbuf[j] ^= ivbuf[j];
        blockEncrypt(&encipher, &keyin, ptbuf, 128, ctbuf);
        for(int j=0;j<16;j++){
            ptbuf[j] = ivbuf[j];
            ivbuf[j] = ctbuf[j];
        }
    }
    file << "\nCT=";
    for(int k=0;k<16;k++){
        file << tohex[ctbuf[k]>>4] << tohex[ctbuf[k]&0x0f];
    }
    /* the first 128 bits come from ctbuf, and
     * the remaining 128 bits from ptbuf (CT9999, and CT9998)
     */
    for(int k=0;k<16;k++) {
        akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ptbuf[k]>>4)];
        akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ptbuf[k] & 0x0f)];
        akey[2*k+32] = tohex[hex[(int)akey[2*k+32]]^(ctbuf[k]>>4)];
        akey[2*k+33] = tohex[(int)hex[(int)akey[2*k+33]]^(ctbuf[k]&0x0f)];
    }
}
file << "\n==========\n";
file.close();
    /*************************************************************************
     *
     * CBC Decrypt MCT -> cbc_d_m.txt
     *
     ************************************************************************/
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
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
for(int i=0;i<16;i++){
    ctbuf[i] = 0;
    ivbuf[i] = 0;
}
/* we will do CBC manually */
cipherInit(&decipher,MODE_ECB,NULL);
for(int i=0;i<400;i++) {
    makeKey(&keyin,DIR_DECRYPT,128,akey);
    file << "\n\nI=" << i << "\n";
    file << "KEY=";
    for(int k=0;k<32;k++)
        file << akey[k];
    file << "\nIV=";
    for(int k=0;k<16;k++)
        file << tohex[ivbuf[k]>>4] << tohex[ivbuf[k]&0x0f];
    file << "\nCT=";
    for(int k=0;k<16;k++)
        file << tohex[ctbuf[k]>>4] << tohex[ctbuf[k]&0x0f];
    for(int k=0;k<10000;k++){
        blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
        for(int j=0;j<16;j++)
            ptbuf[j] ^= ivbuf[j];
        for(int j=0;j<16;j++){
            ivbuf[j] = ctbuf[j];
            ctbuf[j] = ptbuf[j];
        }
    }
    file << "\nPT=";
    for(int k=0;k<16;k++){
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    }
    for(int k=0;k<16;k++){
        akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ptbuf[k]>>4)];
        akey[2*k+1] = tohex[(int)hex[(int)akey[2*k+1]] ^ (ptbuf[k] & 0x0f)];
    }
}
/* 192 bit keys */
file << "\n\n==========\n\nKEYSIZE=192\n";
/* the starting key, IV, and CT are all zeros */
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
for(int i=0;i<16;i++){
    ctbuf[i] = 0;
    ivbuf[i] = 0;
}
/* we will do CBC manually */
cipherInit(&encipher,MODE_ECB,NULL);
for(int i=0;i<400;i++) {
    makeKey(&keyin,DIR_ENCRYPT,192,akey);
    file << "\n\nI=" << i << "\n";
    file << "KEY=";
    for(int k=0;k<48;k++)
        file << akey[k];
    file << "\nIV=";
    for(int k=0;k<16;k++)
        file << tohex[ivbuf[k]>>4] << tohex[ivbuf[k]&0x0f];
    file << "\nCT=";
    for(int k=0;k<16;k++)
        file << tohex[ctbuf[k]>>4] << tohex[ctbuf[k]&0x0f];
    for(int k=0;k<10000;k++){
        blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
        for(int j=0;j<16;j++)
            ptbuf[j] ^= ivbuf[j];
        for(int j=0;j<16;j++){
            ivbuf[j] = ctbuf[j];
            ctbuf[j] = ptbuf[j];
        }
    }
    file << "\nPT=";
    for(int k=0;k<16;k++){
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    }
    /* the first 64 bits come from the end of ivbuf, and
     * the remaining 128 bits from ctbuf (CT9999, and CT9998)
     */
    for(int k=0;k<8;k++) {
        akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ivbuf[k+8]>>4)];
        akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ivbuf[k+8] & 0x0f)];
    }
    for(int k=0;k<16;k++){
        akey[2*k+16] = tohex[hex[(int)akey[2*k+16]]^(ptbuf[k]>>4)];
        akey[2*k+17] = tohex[(int)hex[(int)akey[2*k+17]]^(ptbuf[k]&0x0f)];
    }
}
/* 256 bit keys */
file << "\n\n==========\n\nKEYSIZE=256\n";
/* the starting key, IV, and PT are all zeros */
for(int i=0;i<64;i++)
    akey[i] = '0';
akey[64] = '\0';
for(int i=0;i<16;i++){
    ctbuf[i] = 0;
    ivbuf[i] = 0;
}
/* we will do CBC manually */
cipherInit(&encipher,MODE_ECB,NULL);
for(int i=0;i<400;i++) {
    makeKey(&keyin,DIR_ENCRYPT,256,akey);
    file << "\n\nI=" << i << "\n";
    file << "KEY=";
    for(int k=0;k<64;k++)
        file << akey[k];
    file << "\nIV=";
    for(int k=0;k<16;k++)
        file << tohex[ivbuf[k]>>4] << tohex[ivbuf[k]&0x0f];
    file << "\nCT=";
    for(int k=0;k<16;k++)
        file << tohex[ctbuf[k]>>4] << tohex[ctbuf[k]&0x0f];
    for(int k=0;k<10000;k++){
        blockDecrypt(&decipher, &keyin, ctbuf, 128, ptbuf);
        for(int j=0;j<16;j++)
            ptbuf[j] ^= ivbuf[j];
        for(int j=0;j<16;j++){
            ivbuf[j] = ctbuf[j];
            ctbuf[j] = ptbuf[j];
        }
    }
    file << "\nPT=";
    for(int k=0;k<16;k++){
        file << tohex[ptbuf[k]>>4] << tohex[ptbuf[k]&0x0f];
    }
    /* the first 128 bits come from ctbuf, and
     * the remaining 128 bits from ptbuf (CT9999, and CT9998)
     */
    for(int k=0;k<16;k++) {
        akey[2*k] = tohex[hex[(int)akey[2*k]] ^ (ivbuf[k]>>4)];
        akey[2*k+1] = tohex[hex[(int)akey[2*k+1]] ^ (ivbuf[k] & 0x0f)];
        akey[2*k+32] = tohex[hex[(int)akey[2*k+32]]^(ptbuf[k]>>4)];
        akey[2*k+33] = tohex[(int)hex[(int)akey[2*k+33]]^(ptbuf[k]&0x0f)];
    }
}
file << "\n==========\n";
file.close();
#endif /* MCT */

    return (0);
}
