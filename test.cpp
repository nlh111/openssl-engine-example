#include "mbedtls_engine.h"
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
using namespace std;

int main(int argc, char **argv)
{
    OpensslEcdsaEngine engine;

    ENGINE *e = ENGINE_by_id("mbedtls");
    if(e==NULL){
        cout<<"ENGINE_by_id failed"<<endl;
    }

    char *data = "sjkdfjksdfalsdjkfas";
    const unsigned char *priv = ecdsa_privkey;
    EC_KEY *ec_privkey = EC_KEY_new();
    EC_KEY *res_priv = d2i_ECPrivateKey(&ec_privkey, &priv, sizeof(ecdsa_privkey));

    EVP_PKEY *privkey = EVP_PKEY_new();
    if (!EVP_PKEY_set1_EC_KEY(privkey, res_priv))
    {
        cout << "EVP_PKEY_set1_EC_KEY failed" << endl;
    }

    EVP_MD_CTX *sign_context = sign_context = EVP_MD_CTX_new();
    if (sign_context == NULL)
    {
        cout << "EVP_MD_CTX_new failed" << endl;
    }

    if(!EVP_MD_CTX_init(sign_context)){
        cout<<"EVP_MD_CTX_init failed"<<endl;
    }

    
    if (!EVP_DigestSignInit(sign_context, NULL, EVP_sha256(), NULL, privkey))
    {
        cout << "EVP_DigestSignInit failed" << endl;
    }

    if (!EVP_DigestSignUpdate(sign_context, data, strlen(data)))
    {
        cout << "EVP_DigestSignUpdate failed" << endl;
    }

    size_t sig_len=0;
    if (!EVP_DigestSignFinal(sign_context, NULL, &sig_len)) {
        cout << "EVP_DigestSignFinal failed" << endl;
    }

    if (sig_len <= 0) {
        cout << "sig_len <= 0" << endl;
    }

    cout<<"sig_len:"<<sig_len<<endl;

    unsigned char *sig_value = NULL;
    sig_value = (unsigned char *)OPENSSL_malloc(sig_len);
    if (sig_value == NULL) {
        cout << "OPENSSL_malloc failed" << endl;
    }

    if (!EVP_DigestSignFinal(sign_context, sig_value, &sig_len)) {
        cout<<"EVP_DigestSignFinal failed"<<endl;
    }

    for(int i=0;i<sig_len;i++){
        printf("0x%02x,",sig_value[i]);
        if(i%16==15){
            cout<<endl;
        }
    }

    // if(!EVP_DigestSign(sign_context, sig, &olen, (const unsigned char *)data, strlen(data))){
    //     cout<<"EVP_DigestSign failed"<<endl;
    // }




    return 0;
}

