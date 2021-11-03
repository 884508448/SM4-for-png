#include "utils.h"
#include <fstream>
using namespace std;
// #define DEBUG

void get_err_para(){
    printf("It seems that you have entered the wrong parameters\n");
    printf("Please use \"scli -help\" to check the correct format\n");
}

void help(){
    printf("Help for SM4 CLI 1.0:\n");
    printf("----------Encryption and decryption----------\n");
    printf("scli -E -e source_path objective_path\n   ---Encrypt the png image of source_path with ECB mode and put it to objective_path\n");
    printf("scli -E -c source_path objective_path\n   ---Encrypt the png image of source_path with CBC mode and put it to objective_path\n");
    printf("scli -D -e source_path objective_path\n   ---Decrypt the png image of source_path with ECB mode and put it to objective_path\n");
    printf("scli -D -c source_path objective_path\n   ---Decrypt the png image of source_path with CBC mode and put it to objective_path\n");
    printf("NOTE: All the paths are ABSOLUTE paths\n\n");
    printf("-------------Key and IV settings-------------\n");
    printf("scli -K your_key\n   ---Set your own key\n");
    printf("scli -IV your_IV\n   ---Set your own IV\n");
}

void en_de_cryption(const char* E_D,const char* mode,const char* sou,const char* obj){
    if(strcmp(E_D,"-E")==0){    // encryption
            if(strcmp(mode,"-e")==0){    // ecb model
                enc_pict(sou,obj,true,false);
                return;
            }
            else{   // cbc model
                enc_pict(sou,obj,false,true);
                return;
            }
        }
        else{    // decryption
            if(strcmp(mode,"-e")==0){    // ecb model
                dec_pict(sou,obj,true,false);
                return;
            }
            else{   // cbc model
                dec_pict(sou,obj,false,true);
                return;
            }
        }
}

int main(int argc,char* argv[]){
    #ifdef DEBUG
    // en_de_cryption("-E","-e","C:/VSWS/SM4/pict/stars.png","C:/VSWS/SM4/pict/stars_en.png");
    // en_de_cryption("-D","-e","C:/VSWS/SM4/pict/stars_en.png","C:/VSWS/SM4/pict/stars_de.png");
    en_de_cryption("-E","-e","C:/VSWS/SM4/pict/cartoon_girl.png","C:/VSWS/SM4/pict/cartoon_girl_en.png");
    en_de_cryption("-D","-e","C:/VSWS/SM4/pict/cartoon_girl_en.png","C:/VSWS/SM4/pict/cartoon_girl_de.png");
    system("pause");
    return 0;
    #endif


    uint32_t key[]={0x01234567,0x89abcdef,0xfedcba98,0x76543210};
    uint32_t IV[]={0x01234567,0x89abcdef,0xfedcba98,0x76543210};
    Set_key(key);
    Set_IV(IV);
    KeyExt();
    if(argc==1){
        printf("SM4 CLI 1.0\nProvided by HUANG Xi\nUse \"scli -help\" to know more about it\n");
        return 0;
    }
    if(argc==2&&strcmp(argv[1],"-help")==0){
        help();
        return 0;
    }
    if(argc==5&&(strcmp(argv[1],"-E")==0||strcmp(argv[1],"-D")==0&&strcmp(argv[2],"-e")==0||strcmp(argv[2],"-c")==0)){
        en_de_cryption(argv[1],argv[2],argv[3],argv[4]);
        return 0;
    }
    if(argc==3&&(strcmp(argv[1],"-K")==0)||strcmp(argv[1],"-IV")==0){
        uint32_t len=strlen(argv[2])-1; // strlen count one more
        if(len>128){
            printf("ERROR: %s invalid! Length should be less than 128\n",strcmp(argv[1],"-K")==0?"key":"IV");
            return -1;
        }
        byte* content=new byte[128];
        memcpy(content,argv[2],len);
        for(int i=len;i<128;i++){
            content[i]=0;   // fill with zero
        }
        if(strcmp(argv[1],"-K")==0){
            Set_key((uint32_t*)(content));
            KeyExt();
        }
        else{
            Set_IV((uint32_t*)(content));
        }
        printf("Set successfully!\n");
        cmd_fmt:
        printf("Input command as this format: -E|D -e|c source_path objective_path\n");
        string E_D,mode,sou,obj;
        cin>>E_D>>mode>>sou>>obj;
        if((E_D=="-E"||E_D=="-D")&&(mode=="-e"||mode=="-c")){
            en_de_cryption(E_D.c_str(),mode.c_str(),sou.c_str(),obj.c_str());
            return 0;
        }
        else{
            printf("Format error!\n");
            goto cmd_fmt;
        }
    }
    get_err_para();
    // system("pause");
    return 0;
}