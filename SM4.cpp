#include "SM4.h"

/***********************************************************************************
 * Use unsigned int array to store key, plaintext, and ciphertext
************************************************************************************/
uint32_t key[4], M[4], C[4], IV[4];
uint32_t rk[32];

/***********************************************************************************
 * Tool constants and function definitions
************************************************************************************/
uint32_t RK_4=0xA3B1BAC6, RK_3=0x56AA3350, RK_2=0x677D9197, RK_1=0xB27022DC; 
const uint32_t CK[32] = {  
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,  
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,  
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,  
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,  
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,  
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,  
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,  
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279 
    };
const unsigned char Sbox[256] = {  
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,  
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,  
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,  
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,  
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,  
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,  
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,  
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,  
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,  
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,  
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,  
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,  
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,  
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,  
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,  
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48  
};

inline uint32_t RotL(uint32_t x,uint32_t y){
    assert(y<=32);
    return (x<<y)|(x>>32-y);
}
// Divide a word into four 8 bits parts, translate by sbox, and then splice these parts
inline uint32_t SboxTrans(uint32_t word){
    return uint32_t(Sbox[word>>24&0xff])<<24| uint32_t(Sbox[word>>16&0xff])<<16|
                    uint32_t(Sbox[word>>8&0xff])<<8| uint32_t(Sbox[word&0xff]);
}
inline uint32_t L1(uint32_t x){
    return x^RotL(x,2)^RotL(x,10)^RotL(x,18)^RotL(x,24);
}

inline uint32_t L2(uint32_t x){
    return x^RotL(x,13)^RotL(x,23);
}
inline void swap(uint32_t& a,uint32_t& b){
    a=a^b;
    b=a^b;
    a=a^b;
}

void Set_M(uint32_t* m){
    for(int i=0;i<4;i++){
        M[i]=m[i];
    }
}
void Get_M(uint32_t* m){
    for(int i=0;i<4;i++){
        m[i]=M[i];
    }
}

void Set_C(uint32_t* c){
    for(int i=0;i<4;i++){
        C[i]=c[i];
    }
}
void Get_C(uint32_t* c){
    for(int i=0;i<4;i++){
        c[i]=C[i];
    }
}

void Set_key(uint32_t* k){
    for(int i=0;i<4;i++){
        key[i]=k[i];
    }
}

void Set_IV(uint32_t* iv){
    for(int i=0;i<4;i++){
        IV[i]=iv[i];
    }
}
void Get_IV(uint32_t* iv){
    for(int i=0;i<4;i++){
        iv[i]=IV[i];
    }
}


void KeyExt(){
    uint32_t rk_4=RK_4^key[0],
    rk_3=RK_3^key[1],
    rk_2=RK_2^key[2],
    rk_1=RK_1^key[3];

    rk[0]=RK_4^L2(SboxTrans(rk_3^rk_2^rk_1^CK[0]));
    rk[1]=RK_3^L2(SboxTrans(rk_2^rk_1^rk[0]^CK[1]));
    rk[2]=RK_2^L2(SboxTrans(rk_1^rk[0]^rk[1]^CK[2]));
    rk[3]=RK_1^L2(SboxTrans(rk[0]^rk[1]^rk[2]^CK[3]));

    for (int i=4;i<32;i+=4){
        for (int j=0;j<4;j++){
            int index=i+j;
            rk[index]=rk[index-4]^L2(SboxTrans(rk[index-3]^rk[index-2]^rk[index-1]^CK[index]));
        }
    }
}

void Encrypt(){
    for (int i=0;i<4;i++){
        C[i]=M[i];
    }
    for (int r=0;r<32;r++){
        uint32_t enc_tmp= C[0]^L1(SboxTrans(C[1]^C[2]^C[3]^rk[r]));
        C[0]=C[1];
        C[1]=C[2];
        C[2]=C[3];
        C[3]=enc_tmp;
    }
    swap(C[0],C[3]);
    swap(C[1],C[2]);
}

void Decrypt(){
    for (int i=0;i<4;i++){
        M[i]=C[i];
    }
    for (int r=0;r<32;r++){
        uint32_t dec_tmp= M[0]^L1(SboxTrans(M[1]^M[2]^M[3]^rk[31-r]));
        M[0]=M[1];
        M[1]=M[2];
        M[2]=M[3];
        M[3]=dec_tmp;
    }
    swap(M[0],M[3]);
    swap(M[1],M[2]);
}

void M_XOR(uint32_t* vec){
    for(int i=0;i<4;i++){
        M[i]^=vec[i];
    }
}

// for test
int test(){
    uint32_t k[]={0x01234567,0x89abcdef,0xfedcba98,0x76543210},m[]={0x01234567,0x89abcdef,0xfedcba98,0x76543210};
    Set_key(k);
    Set_M(m);
    KeyExt();
    printf("key array:\n");
    for(int i=0;i<4;i++){
        printf("%08x ",key[i]);
    }
    printf("\n");
    printf("rk array:\n");
    for(int i=0;i<32;i++){
        printf("%08x\n",rk[i]);
    }
    Encrypt();
    printf("encrypt result:\n");
    for(int i=0;i<4;i++){
        printf("%08x ",C[i]);
    }
    printf("\ndecrypt result:\n");
    Decrypt();
    for(int i=0;i<4;i++){
        printf("%08x ",M[i]);
    }
    printf("\n");
    system("pause");
}

