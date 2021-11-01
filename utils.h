#ifndef UTILS_H
#define UTILS_H

#include "SM4.h"
#include "lodepng.h"
#include <vector>
using namespace std;
typedef unsigned char byte;

void enc_pict(const char* file_name,const char* out_name, bool ECB, bool CBC);  // encrypt png picture use specified model
void dec_pict(const char* file_name,const char* out_name, bool ECB, bool CBC); // decrypt png picture use specified model
void rewrite(const char* file_name, uint32_t* key,const char* out_name);


#endif