/***********************************************************************************
 * SM4
 * Homework 1 of the applied cryptography course
 * By HUANG Xi
 * October 30, 2021
************************************************************************************/

#ifndef SM4_H
#define SM4_H
#include <iostream>
#include <assert.h>


/***********************************************************************************
 * Encryption functions
************************************************************************************/
void Set_M(uint32_t* m);
void Get_M(uint32_t* m);
void Set_C(uint32_t* c);
void Get_C(uint32_t* c);
void Set_key(uint32_t* k);
void Set_IV(uint32_t* iv);
void Get_IV(uint32_t* iv);
void M_XOR(uint32_t* vec);
void KeyExt();
void Encrypt();
void Decrypt();

#endif