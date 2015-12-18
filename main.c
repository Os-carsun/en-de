#include <stdio.h>
#include <stdlib.h>
#include  <fcntl.h>
#include <inttypes.h>
/* OpenSSL headers */

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

/* Initializing OpenSSL */
#define FILE_EXTENSION ".cscc"
#define FILE_EXTENSION_LENGTH 5
#define EN_KEY_SIZE 2048
#define KEY_SIZE 2048
#define BUFFER_SIZE 245
#define ENCRYPTED_SIZE 256
#define DECRYPTED_SIZE 245256
#define RAND() (rand() & 0x7fff)  /* ensure only 15-bits */

typedef uint64_t u64;

int padding = RSA_PKCS1_PADDING;

char* PRIVATE_KEY;
char* PUBLIC_KEY;
RSA* ramdomRsa;


RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}
 
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int public_encrypt_byRSA(unsigned char * data,int data_len, unsigned char *encrypted)
{
    if(ramdomRsa == NULL) printf("WTF\n");
    int result = RSA_public_encrypt(data_len,data,encrypted,ramdomRsa,padding);
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}
 
void encryptedFile(char* fileName ){
    
    // char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
    //     "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
    //     "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
    //     "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
    //     "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
    //     "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
    //     "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
    //     "wQIDAQAB\n"\
    //     "-----END PUBLIC KEY-----\n";
    //     printf("%s\n", PUBLIC_KEY);
    //     printf("%s\n", publicKey);
    FILE *input;
    FILE *output;
    unsigned char *encrypted;
    unsigned char *buffer;
    char* outputName = (char*)malloc(sizeof(char*)* strlen(fileName)+FILE_EXTENSION_LENGTH);

    strcpy(outputName, fileName);
    strcat(outputName, FILE_EXTENSION);

    input = fopen(fileName,"rb");
    output = fopen(outputName,"wb+");

    buffer = (unsigned char*) malloc (sizeof(unsigned char)*BUFFER_SIZE);
    memset(buffer,0,BUFFER_SIZE);
    while( fread (buffer,1,BUFFER_SIZE,input) != 0){
        
        
        encrypted = (unsigned char*) malloc (sizeof(unsigned char)*ENCRYPTED_SIZE);
        memset(encrypted,0,ENCRYPTED_SIZE);
        int encrypted_length = public_encrypt_byRSA(buffer,BUFFER_SIZE,encrypted);

        
        fwrite(encrypted,encrypted_length,1,output);
        
        

        buffer = (unsigned char*) malloc (sizeof(unsigned char)*BUFFER_SIZE);
        memset(buffer,0,BUFFER_SIZE);
    }


    fclose(input);
    fclose(output);

    // return rsa;
}

void decryptedFile(char* fileName , unsigned char * privateKey){
    
    FILE *input;  
    FILE *output;
    input = fopen(fileName,"rb");
    unsigned char *decrypted;
    unsigned char  *buffer;
    char* outputName = (char*)malloc(sizeof(char*)* strlen(fileName)-FILE_EXTENSION_LENGTH+1);
    
    strncpy(outputName, fileName, strlen(fileName)-FILE_EXTENSION_LENGTH);
    outputName[strlen(outputName)+1]="\0";
    
    output = fopen(outputName,"wb");

    buffer = (unsigned char*) malloc (sizeof(unsigned char)*ENCRYPTED_SIZE);
    memset(buffer,0,ENCRYPTED_SIZE);
    while( fread (buffer,1,ENCRYPTED_SIZE,input) != 0){
        
        decrypted = (unsigned char*) malloc (sizeof(unsigned char)*ENCRYPTED_SIZE);
        memset(decrypted,0,ENCRYPTED_SIZE);
        int decrypted_length = private_decrypt(buffer,ENCRYPTED_SIZE,privateKey, decrypted);
        if(decrypted_length == -1)
        {
            printLastError("Private Decrypt failed ");
            exit(0);
        }
        
        fwrite(decrypted,decrypted_length,1,output);
        buffer = (unsigned char*) malloc (sizeof(unsigned char)*ENCRYPTED_SIZE);
        memset(buffer,0,ENCRYPTED_SIZE);
    }
   
    fclose(input);
    fclose(output);
}

unsigned long long lrand() {
    srand(time(0));
    return ((u64)RAND()<<48) ^ ((u64)RAND()<<35) ^ ((u64)RAND()<<22) ^
            ((u64)RAND()<< 9) ^ ((u64)RAND()>> 4);
}

void randomKey(){
    int keylen;
    // char *private_key,*public_key;
    unsigned long prime = lrand();
    if (prime % 2 == 0){
        prime -= 1;
    }
    RSA *rsa = RSA_generate_key(KEY_SIZE, prime, 0, 0);
    ramdomRsa = rsa;
    // BIO *bio = BIO_new(BIO_s_mem());

    // PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    // keylen = BIO_pending(bio);
    // PRIVATE_KEY = calloc(keylen+1, 1); /* Null-terminate */
    // BIO_read(bio, PRIVATE_KEY, keylen);

    
    // PEM_write_bio_RSAPublicKey(bio , rsa);
    // keylen = BIO_pending(bio);
    // PUBLIC_KEY = calloc(keylen+1, 1); /* Null-terminate */
    // BIO_read(bio, PUBLIC_KEY, keylen);
    
    // RSA_free(rsa);
}
int main(int argc, char *argv[])
{
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    randomKey();
    



  
    // char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
        // "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
        // "vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
        // "Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
        // "yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
        // "WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
        // "gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
        // "omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
        // "N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
        // "X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
        // "gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
        // "vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
        // "1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
        // "m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
        // "uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
        // "JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
        // "4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
        // "WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
        // "nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
        // "PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
        // "SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
        // "I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
        // "ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
        // "yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
        // "w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
        // "uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
        // "-----END RSA PRIVATE KEY-----\n";

    encryptedFile("1_BS0BI_1200x0.jpg");
    // decryptedFile("1_BS0BI_1200x0.jpg.cscc",PRIVATE_KEY);
 
     


    return 0;
}
