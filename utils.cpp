#include "utils.h"
#include <fstream>

// #define DEBUG

void zero_fill(byte* &raw,uint32_t& len){   // Fill with 0 so that the original data length is a multiple of 16
    int need=16-(len%16);
    if (need!=16){
        byte* data=new byte[len+need];
        for(int i=0;i<len;i++){
            data[i]=raw[i];
        }
        for(int i=len;i<len+need;i++){
            data[i]=0;
        }
        delete[] raw;
        raw=data;
        len+=need;
    }
}

void vec2arr(vector<byte>& vec,byte*& arr){
    arr=new byte[vec.size()];
    for(int i=0;i<vec.size();i++){
        arr[i]=vec[i];
    }
}

void arr2vec(vector<byte>& vec,byte*& arr,uint32_t size){
    vec.resize(size);
    for(int i=0;i<size;i++){
        vec[i]=arr[i];
    }
}

void append_len(const char* file_name,uint32_t len){
    FILE* image=fopen(file_name,"ab");
    fwrite(&len,4,1,image);
    fclose(image);
}

void read_png(const char* file_name, vector<byte>& image, uint32_t& w, uint32_t& h, lodepng::State& state){
    vector<byte> buffer;
    uint32_t error;

    state.decoder.color_convert = 0;
    state.decoder.remember_unknown_chunks = 1; //make it reproduce even unknown chunks in the saved image

    lodepng::load_file(buffer,file_name);
    error = lodepng::decode(image, w, h, state, buffer);
    if(error) {
        std::cout << "decoder error " << error << ": " << lodepng_error_text(error) << std::endl;
        return;
    }

    buffer.clear();
}

void write_png(const char* out_name, vector<byte>& image, uint32_t& w, uint32_t& h, lodepng::State& state){
    vector<byte> buffer;
    uint32_t error;
    state.encoder.text_compression = 1;

    error = lodepng::encode(buffer, image, w, h, state);
    if(error) {
        std::cout << "encoder error " << error << ": " << lodepng_error_text(error) << std::endl;
        return;
    }

    lodepng::save_file(buffer, out_name);
}

/************************************************************************************************
 * ECB model BEGIN
 * **********************************************************************************************/
byte* ecb_encrypt(byte* &data,uint32_t& len){
    zero_fill(data,len);
    assert(len%16==0);
    byte* result=new byte[len];
    int round=len/16;
    for(int i=0;i<round;i++){
        Set_M((uint32_t*)(data+i*16));
        Encrypt();
        Get_C((uint32_t*)(result+i*16));
    }
    return result;
}
byte* ecb_decrypt(const byte* code,uint32_t len){
    if(len%16!=0){
        printf("ERROR: The length of the cipher text should be an integer multiple of 16 bytes!\n");
        return NULL;
    }
    byte* result=new byte[len];
    int round=len/16;
    for(int i=0;i<round;i++){
        Set_C((uint32_t*)(code+i*16));
        Decrypt();
        Get_M((uint32_t*)(result+i*16));
    }
    return result;
}
/************************************************************************************************
 * ECB model END
 * **********************************************************************************************/



/************************************************************************************************
 * CBC model BEGIN
 * **********************************************************************************************/
byte* cbc_encrypt(byte* &data,uint32_t& len){
    zero_fill(data,len);
    assert(len%16==0);
    byte* result=new byte[len];
    int round=len/16;

    // XOR with IV first
    Set_M((uint32_t*)(data));
    uint32_t iv[4];
    Get_IV(iv);
    M_XOR(iv);
    Encrypt();
    Get_C((uint32_t*)(result));

    // cbc encryption round
    for(int i=1;i<round;i++){
        Set_M((uint32_t*)(data+i*16));
        M_XOR((uint32_t*)(result+(i-1)*16));
        Encrypt();
        Get_C((uint32_t*)(result+i*16));
    }
    return result;
}

byte* cbc_decrypt(const byte* code,uint32_t len){
    if(len%16!=0){
        printf("ERROR: The length of the cipher text should be an integer multiple of 16 bytes!\n");
        return NULL;
    }
    byte* result=new byte[len];
    int round=len/16;

    // XOR with IV first
    Set_C((uint32_t*)(code));
    Decrypt();
    uint32_t iv[4];
    Get_IV(iv);
    M_XOR(iv);
    Get_M((uint32_t*)(result));

    // cbc decryption round
    for(int i=1;i<round;i++){
        Set_C((uint32_t*)(code+i*16));
        Decrypt();
        M_XOR((uint32_t*)(code+(i-1)*16));
        Get_M((uint32_t*)(result+i*16));
    }
    return result;
}
/************************************************************************************************
 * CBC model END
 * **********************************************************************************************/




/************************************************************************************************
 * png operation BEGIN
 * **********************************************************************************************/
void enc_pict(const char* file_name,const char* out_name, bool ECB, bool CBC){
    // read png
    vector<byte> image;
    uint32_t w,h;
    lodepng::State state;
    read_png(file_name,image,w,h,state);

    //encode png
    uint32_t origin_len=image.size();
    uint32_t len=origin_len;
    byte* image_arr;
    vec2arr(image,image_arr);
    if(ECB) image_arr=ecb_encrypt(image_arr,len);
    else if(CBC) image_arr=cbc_encrypt(image_arr,len);
    else{
        printf("ERROR: Please check ECB or CBC model!\n");
        return;
    }
    arr2vec(image,image_arr,len);

    // write png
    write_png(out_name,image,w,h,state);

    // append origin len
    append_len(out_name,origin_len);

    #ifdef DEBUG
    printf("w:%d, h:%d\n",w,h);
    printf("origin_len: %d\nlen: %d\n",origin_len,len);
    printf("fill zero: %d\n",len-origin_len);
    #endif
}

void dec_pict(const char* file_name,const char* out_name, bool ECB, bool CBC){
    // read png
    vector<byte> image;
    uint32_t w,h;
    lodepng::State state;
    read_png(file_name,image,w,h,state);

    //decode png
    uint32_t len=image.size();
    byte* image_arr;
    vec2arr(image,image_arr);
    if(ECB) image_arr=ecb_decrypt(image_arr,len);
    else if(CBC) image_arr=cbc_decrypt(image_arr,len);
    else{
        printf("ERROR: Please check ECB or CBC model!\n");
        return;
    }
    arr2vec(image,image_arr,len);

    // write png
    write_png(out_name,image,w,h,state);

    #ifdef DEBUG
    printf("w:%d, h:%d\n",w,h);
    printf("len: %d\n",len);
    #endif
}
/************************************************************************************************
 * png operation END
 * **********************************************************************************************/


// for test
void rewrite(const char* file_name, uint32_t* key,const char* out_name){   // for test
    // read png
    vector<byte> image;
    uint32_t w,h;
    lodepng::State state;
    read_png(file_name,image,w,h,state);
    // write png
    write_png(out_name,image,w,h,state);
}

