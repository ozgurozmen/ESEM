/***********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: testing code for cryptographic functions based on FourQ 
************************************************************************************/   

#include "../FourQ_api.h"
#include "../FourQ_params.h"
 
#include "test_extras.h"
#include <stdio.h>
#include "aes.h"
#include "blake2.h"
#include "zmq.h"

#define HIGH_SPEED 1

#define CMD_REQUEST_VERIFICATION         0x000010

// Benchmark and test parameters 

//For easy testing, no random keys are used in this implementation. secret_key, public_key should be generated new every time.

#if defined(HIGH_SPEED) // This is ESEMv2
    #define BENCH_LOOPS       100000      // Number of iterations per bench
    #define BPV_V             40
    #define ESEM_L            3
    #define BPV_N             128
#else 
    #define BENCH_LOOPS       100000
    #define BPV_V             18
    #define ESEM_L            3
    #define BPV_N             1024
#endif

void print_hex(unsigned char* arr, int len)
{
    int i;
    printf("\n");
    for(i = 0; i < len; i++)
        printf("%x", (unsigned char) arr[i]);
    printf("\n");
}
 
void menu(){
    printf("NOTE: Currently, our implementation only has the communication between the verifier and the server \n");
    printf("NOTE: Therefore, Key Generation, Signer and Verifier should be run on same terminal. \n");        
    // printf("NOTE: Before running the server, key generation should be run once. \n");        
    printf("Select one of the following: \n");
    printf("(1) Key Generation\n");
    printf("(2) Signer\n");
    printf("(3) Server\n");
    printf("(4) Verifier\n");
    printf("(5) Exit\n\n\n");

}

ECCRYPTO_STATUS ESEM_KeyGen(unsigned char sk_aes[32], unsigned char secret_key[32], unsigned char public_key[64], unsigned char *publicAll_1, unsigned char *publicAll_2, unsigned char *publicAll_3, unsigned char  *secretAll_1, unsigned char  *secretAll_2, unsigned char  *secretAll_3, unsigned char tempKey1[32], unsigned char tempKey2[32], unsigned char tempKey3[32]){

    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    block* prf_out;
    unsigned char *prf_out2;
    prf_out = malloc(16*2);
    prf_out2 = malloc(16*2);
    uint64_t i, index;
    unsigned char publicTemp[64];

    Status = PublicKeyGeneration(secret_key, public_key);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    

    block key;
    key = toBlock((uint8_t*)sk_aes);
    setKey(key);

    index = 1;
    ecbEncCounterMode(index,2,prf_out);
    memmove(tempKey1,prf_out,32);

    key = toBlock((uint8_t*)tempKey1);
    setKey(key);

    for (i=0;i<BPV_N;i++){ // To generate the y_i and Y[i]= y_i x G  and publish Y[i] as the public key
        ecbEncCounterMode(i,2,prf_out);
        memmove(prf_out2,prf_out,32);

        modulo_order((digit_t*)prf_out2, (digit_t*)prf_out2);

        Status = PublicKeyGeneration(prf_out2, publicTemp);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        memmove(publicAll_1+i*64, publicTemp, 64);
        memmove(secretAll_1+i*32, prf_out2, 32);
    }


    key = toBlock((uint8_t*)sk_aes);
    setKey(key);

    index = 2;
    ecbEncCounterMode(index,2,prf_out);
    memmove(tempKey2,prf_out,32);

    key = toBlock((uint8_t*)tempKey2);
    setKey(key);

    for (i=0;i<BPV_N;i++){ // To generate the y_i and Y[i]= y_i x G  and publish Y[i] as the public key
        ecbEncCounterMode(i,2,prf_out);
        memmove(prf_out2,prf_out,32);

        modulo_order((digit_t*)prf_out2, (digit_t*)prf_out2);

        Status = PublicKeyGeneration(prf_out2, publicTemp);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        memmove(publicAll_2+i*64, publicTemp, 64);
        memmove(secretAll_2+i*32, prf_out2, 32);
    }



    key = toBlock((uint8_t*)sk_aes);
    setKey(key);

    index = 3;
    ecbEncCounterMode(index,2,prf_out);
    memmove(tempKey3,prf_out,32);

    key = toBlock((uint8_t*)tempKey3);
    setKey(key);

    for (i=0;i<BPV_N;i++){ // To generate the y_i and Y[i]= y_i x G  and publish Y[i] as the public key
        ecbEncCounterMode(i,2,prf_out);
        memmove(prf_out2,prf_out,32);

        modulo_order((digit_t*)prf_out2, (digit_t*)prf_out2);

        Status = PublicKeyGeneration(prf_out2, publicTemp);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        memmove(publicAll_3+i*64, publicTemp, 64);
        memmove(secretAll_3+i*32, prf_out2, 32);
    }

    // print_hex(prf_out2, 32);
    // print_hex(publicTemp, 64);

    free(prf_out);
    free(prf_out2); 

    return ECCRYPTO_SUCCESS;

cleanup:

    free(prf_out);
    free(prf_out2); 

    return Status;

}


ECCRYPTO_STATUS ESEM_Sign(unsigned char sk_aes[32], unsigned char secret_key[32], unsigned char *message, unsigned char *signature){

    // ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;

    block* prf_out;
    unsigned char *prf_out2;
    prf_out = malloc(16*2);
    prf_out2 = malloc(16*2);
    uint64_t i, index, index2;

    unsigned char randValue[16] = {0}; //This is x in the scheme
    unsigned char counter[8] = {0};
    unsigned char hashOutput[36] = {0};

    unsigned char secretTemp[32];
    unsigned char secretTemp2[32];
    unsigned char lastSecret[32];
    digit_t* r = (digit_t*)(lastSecret);
    digit_t* S = (digit_t*)(signature+16);  
    digit_t* Secret = (digit_t*)(secretTemp2);  

    unsigned char tempKey1[32];
    unsigned char tempKey2[32];
    unsigned char tempKey3[32];

    blake2b(randValue, counter, secret_key, 16,8,32);
    // print_hex(randValue, 16);

    memcpy(signature, randValue,  16);

    block key;
    key = toBlock((uint8_t*)sk_aes);
    setKey(key);

    index = 1;
    ecbEncCounterMode(index,2,prf_out);
    memmove(tempKey1,prf_out,32);

    key = toBlock((uint8_t*)tempKey1);
    setKey(key);

    blake2b(hashOutput, randValue, tempKey1, 36, 16, 32);

    index2 = hashOutput[0] + ((hashOutput[1]/64) * 256);

    ecbEncCounterMode(index2,2,prf_out);
    memmove(secretTemp,prf_out,32);

    modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);

    index2 = hashOutput[2] + ((hashOutput[3]/64) * 256);

    ecbEncCounterMode(index2,2,prf_out);
    memmove(secretTemp2,prf_out,32);

    modulo_order((digit_t*)secretTemp2, (digit_t*)secretTemp2);
    add_mod_order((digit_t*)secretTemp, (digit_t*)secretTemp2, r);

    for (i = 2; i < BPV_V; ++i) { 
        index2 = hashOutput[2*i] + ((hashOutput[2*i+1]/64) * 256);
      
        ecbEncCounterMode(index2,2,prf_out);
        memmove(secretTemp,prf_out,32);

        modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);
        add_mod_order((digit_t*)secretTemp, r, r); // Add the r_i's and compute the final r
    }

    key = toBlock((uint8_t*)sk_aes);
    setKey(key);

    index = 2;
    ecbEncCounterMode(index,2,prf_out);
    memmove(tempKey2,prf_out,32);

    key = toBlock((uint8_t*)tempKey2);
    setKey(key);

    blake2b(hashOutput, randValue, tempKey2, 36, 16, 32);

    for (i = 0; i < BPV_V; ++i) { 
        index2 = hashOutput[2*i] + ((hashOutput[2*i+1]/64) * 256);
      
        ecbEncCounterMode(index2,2,prf_out);
        memmove(secretTemp,prf_out,32);

        modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);
        add_mod_order((digit_t*)secretTemp, r, r); // Add the r_i's and compute the final r
    }


    key = toBlock((uint8_t*)sk_aes);
    setKey(key);

    index = 3;
    ecbEncCounterMode(index,2,prf_out);
    memmove(tempKey3,prf_out,32);

    key = toBlock((uint8_t*)tempKey3);
    setKey(key);

    blake2b(hashOutput, randValue, tempKey3, 36, 16, 32);

    for (i = 0; i < BPV_V; ++i) { 
        index2 = hashOutput[2*i] + ((hashOutput[2*i+1]/64) * 256);
      
        ecbEncCounterMode(index2,2,prf_out);
        memmove(secretTemp,prf_out,32);

        modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);
        add_mod_order((digit_t*)secretTemp, r, r); // Add the r_i's and compute the final r -- Last r is calculated here (if l = 3)
    }

    unsigned char hashedMsg[32] = {0}; 
    blake2b(hashedMsg, message, randValue, 32, 32, 16);

    modulo_order((digit_t*)hashedMsg, (digit_t*)hashedMsg);

    to_Montgomery((digit_t*)hashedMsg, S);
    to_Montgomery((digit_t*)secret_key, Secret);
    Montgomery_multiply_mod_order(S, Secret, S);
    from_Montgomery(S, S);
    subtract_mod_order(r, S, S);



    free(prf_out);
    free(prf_out2); 

    return ECCRYPTO_SUCCESS;

}

ECCRYPTO_STATUS ESEM_Sign_v2(unsigned char secret_key[32], unsigned char *message, unsigned char *secretAll_1, unsigned char *secretAll_2, unsigned char *secretAll_3, unsigned char tempKey1[32], unsigned char tempKey2[32], unsigned char tempKey3[32], unsigned char *signature){

    uint64_t i;

    unsigned char randValue[16] = {0}; //This is x in the scheme
    unsigned char counter[8] = {0};
    unsigned char hashOutput[40] = {0};

    unsigned char secretTemp[32];
    unsigned char secretTemp2[32];
    unsigned char lastSecret[32];
    digit_t* r = (digit_t*)(lastSecret);
    digit_t* S = (digit_t*)(signature+16);  
    digit_t* Secret = (digit_t*)(secretTemp2);  


    blake2b(randValue, counter, secret_key, 16,8,32);

    memcpy(signature, randValue,  16);

    blake2b(hashOutput, randValue, tempKey1, 40, 16, 32);

    hashOutput[0] = hashOutput[0]/2;
    memmove(secretTemp, secretAll_1 + hashOutput[0]*32, 32);
    // modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);

    hashOutput[1] = hashOutput[1]/2;
    memmove(secretTemp2, secretAll_1 + hashOutput[1]*32, 32);
    // modulo_order((digit_t*)secretTemp2, (digit_t*)secretTemp2);
    add_mod_order((digit_t*)secretTemp, (digit_t*)secretTemp2, r);

    for (i = 2; i < BPV_V; ++i) { 
        hashOutput[i] = hashOutput[i]/2;
        memmove(secretTemp,secretAll_1 + hashOutput[i]*32, 32);

        // modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);
        add_mod_order((digit_t*)secretTemp, r, r); // Add the r_i's and compute the final r
    }


    blake2b(hashOutput, randValue, tempKey2, 40, 16, 32);

    for (i = 0; i < BPV_V; ++i) { 
        hashOutput[i] = hashOutput[i]/2;
        memmove(secretTemp,secretAll_2 + hashOutput[i]*32, 32);

        // modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);
        add_mod_order((digit_t*)secretTemp, r, r); // Add the r_i's and compute the final r
    }


    blake2b(hashOutput, randValue, tempKey3, 40, 16, 32);
    
    for (i = 0; i < BPV_V; ++i) { 
        hashOutput[i] = hashOutput[i]/2;
        memmove(secretTemp,secretAll_3 + hashOutput[i]*32, 32);

        // modulo_order((digit_t*)secretTemp, (digit_t*)secretTemp);
        add_mod_order((digit_t*)secretTemp, r, r); // Add the r_i's and compute the final r
    }


    unsigned char hashedMsg[32] = {0}; 
    blake2b(hashedMsg, message, randValue, 32, 32, 16);

    modulo_order((digit_t*)hashedMsg, (digit_t*)hashedMsg);

    to_Montgomery((digit_t*)hashedMsg, S);
    to_Montgomery((digit_t*)secret_key, Secret);
    Montgomery_multiply_mod_order(S, Secret, S);
    from_Montgomery(S, S);
    subtract_mod_order(r, S, S);



    return ECCRYPTO_SUCCESS;

}


ECCRYPTO_STATUS ESEM_Server(unsigned char *publicAll_1, unsigned char *publicAll_2, unsigned char *publicAll_3, unsigned char tempKey1[32], unsigned char tempKey2[32], unsigned char tempKey3[32]){

    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;

    unsigned char randValue[16];
    unsigned char hashOutput[36] = {0};
    uint64_t i, index2;
    unsigned char lastPublic1[64];
    unsigned char lastPublic2[64];
    unsigned char lastPublic3[64];
    unsigned char publicTemp[64];   
    point_extproj_t TempExtproj1, TempExtproj2, TempExtproj3;
    point_extproj_precomp_t TempExtprojPre1, TempExtprojPre2, TempExtprojPre3;
    point_extproj_t RVerify1, RVerify2, RVerify3;

    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int rc = zmq_bind (responder, "tcp://*:5555");

    zmq_recv (responder, randValue, 16, 0);
    print_hex(randValue, 16);


    blake2b(hashOutput, randValue, tempKey1, 36, 16, 32);

    index2 = hashOutput[0] + ((hashOutput[1]/64) * 256);
    
    memmove(publicTemp,publicAll_1 +64*index2, 64);
    point_setup((point_affine*)publicTemp, RVerify1);

    index2 = hashOutput[2] + ((hashOutput[3]/64) * 256);

    memmove(publicTemp,publicAll_1 +64*index2, 64);
    point_setup((point_affine*)publicTemp, TempExtproj1);

    R1_to_R2(TempExtproj1, TempExtprojPre1);
    eccadd(TempExtprojPre1, RVerify1);


    for (i = 2; i < BPV_V; ++i) { // Same as above happens in the loop
        index2 = hashOutput[2*i] + ((hashOutput[2*i+1]/64) * 256);

        memmove(publicTemp,publicAll_1 +64*index2,64);
        point_setup((point_affine*)publicTemp, TempExtproj1);

        R1_to_R2(TempExtproj1, TempExtprojPre1);
        eccadd(TempExtprojPre1, RVerify1);   // Add the R[i]'s and compute the final R
    }

    eccnorm(RVerify1, (point_affine*)lastPublic1);

    zmq_send(responder, lastPublic1, 64, 0);

    zmq_recv (responder, randValue, 16, 0);
    print_hex(randValue, 16);



    blake2b(hashOutput, randValue, tempKey2, 36, 16, 32);

    index2 = hashOutput[0] + ((hashOutput[1]/64) * 256);
    
    memmove(publicTemp,publicAll_2 +64*index2, 64);
    point_setup((point_affine*)publicTemp, RVerify2);

    index2 = hashOutput[2] + ((hashOutput[3]/64) * 256);

    memmove(publicTemp,publicAll_2 +64*index2, 64);
    point_setup((point_affine*)publicTemp, TempExtproj2);

    R1_to_R2(TempExtproj2, TempExtprojPre2);
    eccadd(TempExtprojPre2, RVerify2);


    for (i = 2; i < BPV_V; ++i) { // Same as above happens in the loop
        index2 = hashOutput[2*i] + ((hashOutput[2*i+1]/64) * 256);

        memmove(publicTemp,publicAll_2 +64*index2,64);
        point_setup((point_affine*)publicTemp, TempExtproj2);

        R1_to_R2(TempExtproj2, TempExtprojPre2);
        eccadd(TempExtprojPre2,RVerify2);   // Add the R[i]'s and compute the final R
    }

    eccnorm(RVerify2, (point_affine*)lastPublic2);

    zmq_send(responder, lastPublic2, 64, 0);

    zmq_recv (responder, randValue, 16, 0);
    print_hex(randValue, 16);


    blake2b(hashOutput, randValue, tempKey3, 36, 16, 32);

    index2 = hashOutput[0] + ((hashOutput[1]/64) * 256);
    
    memmove(publicTemp,publicAll_3 +64*index2, 64);
    point_setup((point_affine*)publicTemp, RVerify3);

    index2 = hashOutput[2] + ((hashOutput[3]/64) * 256);

    memmove(publicTemp,publicAll_3 +64*index2, 64);
    point_setup((point_affine*)publicTemp, TempExtproj3);

    R1_to_R2(TempExtproj3, TempExtprojPre3);
    eccadd(TempExtprojPre3, RVerify3);


    for (i = 2; i < BPV_V; ++i) { // Same as above happens in the loop
        index2 = hashOutput[2*i] + ((hashOutput[2*i+1]/64) * 256);

        memmove(publicTemp,publicAll_3 +64*index2,64);
        point_setup((point_affine*)publicTemp, TempExtproj3);

        R1_to_R2(TempExtproj3, TempExtprojPre3);
        eccadd(TempExtprojPre3,RVerify3);   // Add the R[i]'s and compute the final R
    }

    eccnorm(RVerify3, (point_affine*)lastPublic3);

    zmq_send(responder, lastPublic3, 64, 0);


    return Status;

}


ECCRYPTO_STATUS ESEM_Server_v2(unsigned char *publicAll_1, unsigned char *publicAll_2, unsigned char *publicAll_3, unsigned char tempKey1[32], unsigned char tempKey2[32], unsigned char tempKey3[32]){

    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;

    unsigned char randValue[16];
    unsigned char hashOutput[40] = {0};
    uint64_t i, index2;
    unsigned char lastPublic1[64];
    unsigned char lastPublic2[64];
    unsigned char lastPublic3[64];
    unsigned char publicTemp[64];   
    point_extproj_t TempExtproj1, TempExtproj2, TempExtproj3;
    point_extproj_precomp_t TempExtprojPre1, TempExtprojPre2, TempExtprojPre3;
    point_extproj_t RVerify1, RVerify2, RVerify3;

    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int rc = zmq_bind (responder, "tcp://*:5555");

    zmq_recv (responder, randValue, 16, 0);
    print_hex(randValue, 16);


    blake2b(hashOutput, randValue, tempKey1, 40, 16, 32);

    index2 = hashOutput[0]/2;
    
    memmove(publicTemp,publicAll_1 +64*index2, 64);
    point_setup((point_affine*)publicTemp, RVerify1);

    index2 = hashOutput[1]/2;

    memmove(publicTemp,publicAll_1 +64*index2, 64);
    point_setup((point_affine*)publicTemp, TempExtproj1);

    R1_to_R2(TempExtproj1, TempExtprojPre1);
    eccadd(TempExtprojPre1, RVerify1);


    for (i = 2; i < BPV_V; ++i) { // Same as above happens in the loop
        index2 = hashOutput[i]/2;

        memmove(publicTemp,publicAll_1 +64*index2,64);
        point_setup((point_affine*)publicTemp, TempExtproj1);

        R1_to_R2(TempExtproj1, TempExtprojPre1);
        eccadd(TempExtprojPre1, RVerify1);   // Add the R[i]'s and compute the final R
    }

    eccnorm(RVerify1, (point_affine*)lastPublic1);

    zmq_send(responder, lastPublic1, 64, 0);

    zmq_recv (responder, randValue, 16, 0);
    print_hex(randValue, 16);



    blake2b(hashOutput, randValue, tempKey2, 40, 16, 32);

    index2 = hashOutput[0]/2;
    
    memmove(publicTemp,publicAll_2 +64*index2, 64);
    point_setup((point_affine*)publicTemp, RVerify2);

    index2 = hashOutput[1]/2;

    memmove(publicTemp,publicAll_2 +64*index2, 64);
    point_setup((point_affine*)publicTemp, TempExtproj2);

    R1_to_R2(TempExtproj2, TempExtprojPre2);
    eccadd(TempExtprojPre2, RVerify2);


    for (i = 2; i < BPV_V; ++i) { // Same as above happens in the loop
        index2 = hashOutput[i]/2;

        memmove(publicTemp,publicAll_2 +64*index2,64);
        point_setup((point_affine*)publicTemp, TempExtproj2);

        R1_to_R2(TempExtproj2, TempExtprojPre2);
        eccadd(TempExtprojPre2,RVerify2);   // Add the R[i]'s and compute the final R
    }

    eccnorm(RVerify2, (point_affine*)lastPublic2);

    zmq_send(responder, lastPublic2, 64, 0);

    zmq_recv (responder, randValue, 16, 0);
    print_hex(randValue, 16);


    blake2b(hashOutput, randValue, tempKey3, 40, 16, 32);

    index2 = hashOutput[0]/2;
    
    memmove(publicTemp,publicAll_3 +64*index2, 64);
    point_setup((point_affine*)publicTemp, RVerify3);

    index2 = hashOutput[1]/2;

    memmove(publicTemp,publicAll_3 +64*index2, 64);
    point_setup((point_affine*)publicTemp, TempExtproj3);

    R1_to_R2(TempExtproj3, TempExtprojPre3);
    eccadd(TempExtprojPre3, RVerify3);


    for (i = 2; i < BPV_V; ++i) { // Same as above happens in the loop
        index2 = hashOutput[i]/2;

        memmove(publicTemp,publicAll_3 +64*index2,64);
        point_setup((point_affine*)publicTemp, TempExtproj3);

        R1_to_R2(TempExtproj3, TempExtprojPre3);
        eccadd(TempExtprojPre3,RVerify3);   // Add the R[i]'s and compute the final R
    }

    eccnorm(RVerify3, (point_affine*)lastPublic3);

    zmq_send(responder, lastPublic3, 64, 0);

    zmq_close (responder);
    zmq_ctx_destroy (context);

    return Status;

}


ECCRYPTO_STATUS ESEM_Verifier(unsigned char *signature,  unsigned char *message, unsigned char public_key[64]){

    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;

    unsigned char public_value1[64];
    unsigned char public_value2[64];
    unsigned char public_value3[64];
    unsigned char lastPublic[64];
    unsigned char lastPublic_Verify[64];


    point_extproj_t TempExtproj;
    point_extproj_precomp_t TempExtprojPre;
    point_extproj_t RVerify;


    void *context = zmq_ctx_new ();
    void *requester = zmq_socket (context, ZMQ_REQ);
    zmq_connect (requester, "tcp://localhost:5555");

    zmq_send (requester, signature, 16, 0);
    zmq_recv (requester, public_value1, 64, 0);

    zmq_send (requester, signature, 16, 0);
    zmq_recv (requester, public_value2, 64, 0);

    zmq_send (requester, signature, 16, 0);
    zmq_recv (requester, public_value3, 64, 0);


    point_setup((point_affine*)public_value1, RVerify);
    point_setup((point_affine*)public_value2, TempExtproj);

    R1_to_R2(TempExtproj, TempExtprojPre);
    eccadd(TempExtprojPre, RVerify);

    point_setup((point_affine*)public_value3, TempExtproj);

    R1_to_R2(TempExtproj, TempExtprojPre);
    eccadd(TempExtprojPre, RVerify);   // Add the R[i]'s and compute the final R

    eccnorm(RVerify, (point_affine*)lastPublic);

    unsigned char hashedMsg[32] = {0}; 
    blake2b(hashedMsg, message, signature, 32, 32, 16);

    modulo_order((digit_t*)hashedMsg, (digit_t*)hashedMsg);


    ecc_mul_double((digit_t*)(signature+16), (point_affine*)public_key, (digit_t*)hashedMsg, (point_affine*)lastPublic_Verify);

    if(memcmp(lastPublic, lastPublic_Verify, 64) == 0)
        printf("Verified");
    else
        printf("Not Verified");

    zmq_close (requester);
    zmq_ctx_destroy (context);

    return Status;

}





int main()
{
    //AES Key
    unsigned char sk_aes[32] = {0x54, 0xa2, 0xf8, 0x03, 0x1d, 0x18, 0xac, 0x77, 0xd2, 0x53, 0x92, 0xf2, 0x80, 0xb4, 0xb1, 0x2f, 0xac, 0xf1, 0x29, 0x3f, 0x3a, 0xe6, 0x77, 0x7d, 0x74, 0x15, 0x67, 0x91, 0x99, 0x53, 0x69, 0xc5}; 

    //Schnorr Key
    unsigned char secret_key[32] =  {0x54, 0xa2, 0xf8, 0x03, 0x1d, 0x18, 0xac, 0x77, 0xd2, 0x53, 0x92, 0xf2, 0x80, 0xb4, 0xb1, 0x2f, 0xac, 0xf1, 0x29, 0x3f, 0x3a, 0xe6, 0x77, 0x7d, 0x74, 0x15, 0x67, 0x91, 0x99, 0x53, 0x69, 0xc5}; 
    unsigned char *publicAll_1, *publicAll_2, *publicAll_3, *secretAll_1, *secretAll_2, *secretAll_3, *message, *signature;
    unsigned char tempKey1[32], tempKey2[32], tempKey3[32], public_key[64]; //These are the keys to be shared with Parties.
    publicAll_1 = malloc(BPV_N*64);
    publicAll_2 = malloc(BPV_N*64);
    publicAll_3 = malloc(BPV_N*64);
    secretAll_1 = malloc(BPV_N*32);
    secretAll_2 = malloc(BPV_N*32);
    secretAll_3 = malloc(BPV_N*32);
    message = malloc(32);
    signature = malloc(48);
    memset(message, 0, 32);
    uint64_t benchLoop;
    benchLoop = 0;

    //  Benchmarking variables 
    double SignTime, VerifyTime;
    SignTime = 0.0;
    VerifyTime = 0.0;
    clock_t start, start2;
    clock_t end, end2; 
    // unsigned long long cycles, cycles1, cycles2;     
    // unsigned long long vcycles, vcycles1, vcycles2;

    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    int userType;

    modulo_order((digit_t*)secret_key, (digit_t*)secret_key);

    Status = ESEM_KeyGen(sk_aes, secret_key, public_key, publicAll_1, publicAll_2, publicAll_3, secretAll_1, secretAll_2, secretAll_3, tempKey1, tempKey2, tempKey3);
    if (Status != ECCRYPTO_SUCCESS) {
        printf("Problem Occurred in KeyGen");
    }

#if defined(HIGH_SPEED)
    printf("High Speed\n");
    for(benchLoop = 0; benchLoop <BENCH_LOOPS; benchLoop++){
        start = clock();
        Status = ESEM_Sign_v2(secret_key, message, secretAll_1, secretAll_2, secretAll_3, tempKey1, tempKey2, tempKey3, signature);
        end = clock();
        SignTime = SignTime +(double)(end-start);
    }
#else 
    for(benchLoop = 0; benchLoop <BENCH_LOOPS; benchLoop++){
        start = clock();
        Status = ESEM_Sign(sk_aes, secret_key, message, signature);
        end = clock();
        SignTime = SignTime +(double)(end-start);
    }
#endif
    if (Status != ECCRYPTO_SUCCESS) {
        printf("Problem Occurred in Sign");
    }

    printf("%fus per sign\n", ((double) (SignTime * 1000)) / CLOCKS_PER_SEC / BENCH_LOOPS * 1000);
    print_hex(signature, 48);


    printf("This is a proof-of-concept implementation!!! \n");


    while(1){
        menu();

        scanf ("%d",&userType);
        if(userType==1){
            printf("Key Generation\n");
            Status = ESEM_KeyGen(sk_aes, secret_key, public_key, publicAll_1, publicAll_2, publicAll_3, secretAll_1, secretAll_2, secretAll_3, tempKey1, tempKey2, tempKey3);
            if (Status != ECCRYPTO_SUCCESS) {
                printf("Problem Occurred in KeyGen");
            }
        }
        else if(userType==2){
            printf("Signer\n");
#if defined(HIGH_SPEED)
            printf("High Speed\n");
            // for(benchLoop = 0; benchLoop <BENCH_LOOPS; benchLoop++){
                // start = clock();
            Status = ESEM_Sign_v2(secret_key, message, secretAll_1, secretAll_2, secretAll_3, tempKey1, tempKey2, tempKey3, signature);
                // end = clock();
                // SignTime = SignTime +(double)(end-start);
            // }
#else 
            // for(benchLoop = 0; benchLoop <BENCH_LOOPS; benchLoop++){
                // start = clock();
            Status = ESEM_Sign(sk_aes, secret_key, message, signature);
                // end = clock();
                // SignTime = SignTime +(double)(end-start);
            // }
#endif
            if (Status != ECCRYPTO_SUCCESS) {
                printf("Problem Occurred in Sign");
            }

            // printf("%fus per sign\n", ((double) (SignTime * 1000)) / CLOCKS_PER_SEC / BENCH_LOOPS * 1000);
            print_hex(signature, 48);
            // SignTime = 0.0;
        }
        else if(userType==3){
            printf("Server\n");
#if defined(HIGH_SPEED)
            Status = ESEM_Server_v2(publicAll_1, publicAll_2, publicAll_3, tempKey1, tempKey2, tempKey3);
#else
            Status = ESEM_Server(publicAll_1, publicAll_2, publicAll_3, tempKey1, tempKey2, tempKey3);
#endif

            printf("Three (l) different servers are simulated in a single one, so three rounds of communication happens");
            if (Status != ECCRYPTO_SUCCESS) {
                printf("Problem Occurred in Sign");
            }
        }
        else if(userType==4){
            printf("Verifier\n");
            // memset(message, 1, 32);
            ESEM_Verifier(signature, message, public_key);
        }
        else if(userType==5){
            printf("Exiting\n");
            goto cleanup;
        }
        else
            goto cleanup;
    }
    
    


cleanup:


    
    
    free(publicAll_1);
    free(publicAll_2);
    free(publicAll_3);

    free(secretAll_1);
    free(secretAll_2);
    free(secretAll_3);
    free(message);
    return Status;
 
}
