#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
/*
 gcc /Users/lelopez/Downloads/tiny-AES-c-master/test.c
 /Users/lelopez/Downloads/tiny-AES-c-master/aes.h
 /Users/lelopez/Downloads/tiny-AES-c-master/aes.c

 ./a.out
*/
#define ECB 1

#include "aes.h"


static void phex(uint8_t* str);
static void test_encrypt_ecb_verbose(void);


int main(void)
{

#ifdef AES128
    printf("\nTesting AES128\n\n");
#endif

    test_encrypt_ecb_verbose();

    return 0;
}


// prints string as hex
static void phex(uint8_t* str)
{

#ifdef AES128
    uint8_t len = 16;
#endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%c", str[i]);
    printf("\n");
}

static void test_encrypt_ecb_verbose(void)
{
    // Example of more verbose verification

    uint8_t i, buf[64], buf2[64];

    // 128bit key
    uint8_t key[16] =        { (uint8_t) 0x45, (uint8_t) 0x43, (uint8_t) 0x45, (uint8_t) 0x34, (uint8_t) 0x34, (uint8_t) 0x33, (uint8_t) 0x37, (uint8_t) 0x20, (uint8_t) 0x41, (uint8_t) 0x45, (uint8_t) 0x53, (uint8_t) 0x2d, (uint8_t) 0x6b, (uint8_t) 0x45, (uint8_t) 0x79, (uint8_t) 0x0a };
    // 512bit text
    uint8_t plain_text[64] = { (uint8_t) 0x45, (uint8_t) 0x43, (uint8_t) 0x45, (uint8_t) 0x34, (uint8_t) 0x34, (uint8_t) 0x33, (uint8_t) 0x37, (uint8_t) 0x20, (uint8_t) 0x74, (uint8_t) 0x65, (uint8_t) 0x73, (uint8_t) 0x74, (uint8_t) 0x41, (uint8_t) 0x45, (uint8_t) 0x53, (uint8_t) 0x0d,
                               (uint8_t) 0x45, (uint8_t) 0x43, (uint8_t) 0x45, (uint8_t) 0x34, (uint8_t) 0x34, (uint8_t) 0x33, (uint8_t) 0x37, (uint8_t) 0x20, (uint8_t) 0x74, (uint8_t) 0x65, (uint8_t) 0x73, (uint8_t) 0x74, (uint8_t) 0x41, (uint8_t) 0x45, (uint8_t) 0x53, (uint8_t) 0x0d,
                               (uint8_t) 0x45, (uint8_t) 0x43, (uint8_t) 0x45, (uint8_t) 0x34, (uint8_t) 0x34, (uint8_t) 0x33, (uint8_t) 0x37, (uint8_t) 0x20, (uint8_t) 0x74, (uint8_t) 0x65, (uint8_t) 0x73, (uint8_t) 0x74, (uint8_t) 0x41, (uint8_t) 0x45, (uint8_t) 0x53, (uint8_t) 0x0d,
                               (uint8_t) 0x45, (uint8_t) 0x43, (uint8_t) 0x45, (uint8_t) 0x34, (uint8_t) 0x34, (uint8_t) 0x33, (uint8_t) 0x37, (uint8_t) 0x20, (uint8_t) 0x74, (uint8_t) 0x65, (uint8_t) 0x73, (uint8_t) 0x74, (uint8_t) 0x41, (uint8_t) 0x45, (uint8_t) 0x53, (uint8_t) 0x0d };

    memset(buf, 0, 64);
    memset(buf2, 0, 64);

    // print text to encrypt, key and IV
    printf("ECB encrypt verbose:\n\n");
    printf("plain text:\n");
    for (i = (uint8_t) 0; i < (uint8_t) 4; ++i)
    {
        phex(plain_text + i * (uint8_t) 16);
    }
    printf("\n");

    printf("key:\n");
    phex(key);
    printf("\n");

    // print the resulting cipher as 4 x 16 byte strings
    printf("ciphertext:\n");

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    for (i = 0; i < 4; ++i)
    {
      AES_ECB_encrypt(&ctx, plain_text + (i * 16));
      phex(plain_text + (i * 16));
    }
    printf("\n");
}


static void test_decrypt_ecb(void)
{
#ifdef AES128
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t in[]  = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
#elif defined(AES192)
    uint8_t key[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                      0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t in[]  = { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc };
#elif defined(AES256)
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t in[]  = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };
#endif

    uint8_t out[]   = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    struct AES_ctx ctx;

    AES_init_ctx(&ctx, key);
    AES_ECB_decrypt(&ctx, in);

    printf("ECB decrypt: ");

    if (0 == memcmp((char*) out, (char*) in, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}
