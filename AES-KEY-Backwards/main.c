//
//  main.c
//  AES-KEY-Backwards
//
//  Created by Ilja Rozhko on 10/01/2017.
//  Copyright © 2017 IR Works. All rights reserved.
//

#include <stdio.h>
#define DEBUG_MODE 1

uint8_t sbox[256];

/**
 * The RC table (in this case in full size, for AES-128 only index 1-10 are used.)
 * source: @link: https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 */
unsigned char rc[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

void initialize_aes_sbox();

void aesRoundForward( uint32_t key[], int startRound );
void aesRoundBackward( uint32_t key[], int startRound );

int gFunction( uint32_t input, int round  );
void assignment1a();
void assignment1b();
void assignment2b();

int main(int argc, const char * argv[]) {
    initialize_aes_sbox();
    assignment1a();
    assignment1b();
    assignment2b();
    
    return 0;
}

void assignment1a() {
    printf("\nIntrodcution into cryptography assignment 1a):\n\n");
    
    uint32_t key[44];
    key[0] = 0x00000000;
    key[1] = 0xAABBCCDD;
    key[2] = 0x11223344;
    key[3] = 0xFFFFFFFF;
    
    aesRoundForward( key, 1);
}

void assignment1b() {
    printf("\nIntrodcution into cryptography assignment 1b):\n\n");
    
    /* 0xDECAFBAD, 0xC0DEBA5E, 0xDEADC0DE, 0xBADC0DED */
    uint32_t key[44];
    key[0] = 0xDECAFBAD;
    key[1] = 0xC0DEBA5E;
    key[2] = 0xDEADC0DE;
    key[3] = 0xBADC0DED;
    
    aesRoundForward( key, 1);
}

void assignment2b() {
    
    printf("\nIntrodcution into cryptography assignment 2b):\n\n");
    
    /* 0x8821DF9E, 0x1255D045, 0x5E9A36F3, 0x29BEDB5E */
    uint32_t key[44];
    key[40] = 0x8821DF9E;
    key[41] = 0x1255D045;
    key[42] = 0x5E9A36F3;
    key[43] = 0x29BEDB5E;
    
    aesRoundBackward( key, 9);
}

/**
 * Calculates the normal AES-128 key schedule.
 * @param key as byte array (32 bytes)
 * @param startRound the AES round number this key belongs to
 */
void aesRoundForward( uint32_t key[], int startRound ) {
    
    for ( int currentRound = startRound; currentRound <= 10; currentRound++ ) {
        printf("--- AES-Round %i ---\n", currentRound);
        
        //first operator, with gFunction
        key[4 * currentRound] = gFunction(key[4 * currentRound - 1], currentRound) ^ key[4 * ( currentRound - 1 )];
        printf( "key[%i] = 0x%04x\n", 4 * currentRound, key[4 * currentRound]);
        
        //the three other fields, they are just XORed
        for ( int j = 1; j < 4; j++ ) {
            int keyIndex    = 4 * currentRound + j;
            uint32_t keyVal = key[4 * currentRound + j - 1] ^ key[4 * (currentRound - 1) + j];
            
            key[keyIndex] = keyVal;
            
            printf( "key[%i] = 0x%04x\n", keyIndex, keyVal);
        }
        
        printf("\n");
    }
}

/**
 * Calculates the AES-128 key schedule backwards.
 * @param key as byte array (32 bytes)
 * @param startRound the AES round number this key belongs to
 */
void aesRoundBackward( uint32_t key[], int startRound ) {
    
    for ( int currentRound = startRound; currentRound >= 0; currentRound-- ) {
        printf("--- AES-B-Round %i ---\n", currentRound);
    
        //first XOR the three other fields, since we are going backwards
        for ( int j = 3; j > 0; j-- ) {
            int keyIndex    = 4 * currentRound + j;
            uint32_t keyVal = key[4 * currentRound + j + 3] ^ key[4 * (currentRound + 1) + j];
            
            key[keyIndex] = keyVal;
            
            printf( "key[%i] = 0x%04x", keyIndex, keyVal );
#ifdef DEBUG_MODE
            printf( " (key[%i] ^ key[%i])", 4 * currentRound + j + 3, 4 * (currentRound + 1) + j);
#endif
            printf( "\n" );
        }
        
        //last operator, with gFunction
        key[4 * currentRound] = gFunction(key[4 * currentRound + 3], currentRound) ^ key[4 * ( currentRound + 1 )];
        printf( "key[%i] = 0x%04x\n", 4 * currentRound, key[4 * currentRound]);
        
        printf("\n");
    }
}

/**
 * Calculates the gFunction of AES for the given input WORD.
 * @param input as bytes (32 bytes)
 * @param round the AES round number
 */
int gFunction( uint32_t input, int round ) {
    uint32_t output = -1;
    
    int v1 = ((input >> 16) & 0xFF );
    int v2 = ((input >> 8)  & 0xFF );
    int v3 = ((input >> 0)  & 0xFF );
    int v0 = ((input >> 24) & 0xFF );
    
    output = (sbox[v0] << 0) | (sbox[v3] << 8) | (sbox[v2] << 16) | ((rc[round] ^ sbox[v1]) << 24);
    
#ifdef DEBUG_MODE
    printf( "g-input: 0x%04x\n", input );
    
    printf( "v1 = 0x%02x\n", v1);
    printf( "v2 = 0x%02x\n", v2);
    printf( "v3 = 0x%02x\n", v3);
    printf( "v0 = 0x%02x\n", v0);
    
    printf( "S(v1) = 0x%02x\n", sbox[v1]);
    printf( "RC[%i] ^ S(v1) = 0x%02x\n", round, rc[round] ^ sbox[v1]);
    
    printf( "S(v2) = 0x%02x\n", sbox[v2]);
    printf( "S(v3) = 0x%02x\n", sbox[v3]);
    printf( "S(v0) = 0x%02x\n", sbox[v0]);
    
    printf( "g-output = 0x%04x\n", output);
#endif
    
    return output;
}

/**
 * The S-Box generation for AES.
 * source: @link: https://en.wikipedia.org/wiki/Rijndael_S-box#Example_implementation
 */
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

void initialize_aes_sbox() {
    uint8_t p = 1, q = 1;
    
    /* loop invariant: p * q == 1 in the Galois field */
    do {
        /* multiply p by 2 */
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
        
        /* divide q by 2 */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;
        
        /* compute the affine transformation */
        uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
        
        sbox[p] = xformed ^ 0x63;
    } while (p != 1);
    
    /* 0 is a special case since it has no inverse */
    sbox[0] = 0x63;
}
