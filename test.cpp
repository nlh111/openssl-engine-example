#include "mbedtls_engine.h"
#include <algorithm>
#include <iostream>
#include <openssl/conf.h>
#include <string>
#include <vector>
using namespace std;

int main(int argc, char **argv)
{
    OpensslEcdsaEngine engine;
    OPENSSL_load_builtin_modules();
    ENGINE_load_dynamic();

    // load cnf file
    // CONF *conf = NULL;
    // char openssl_cnf_path[] = "../mbedtls_ecdsa.cnf";
    // if (CONF_modules_load_file(openssl_cnf_path,"openssl_conf" , 0)!=1)
    // {
    //     cout << "CONF_modules_load_file failed" << endl;
    //     cout<<ERR_error_string(ERR_get_error(),NULL)<<endl;
    // }
    // load engine
    ENGINE *e = ENGINE_by_id("mbedtls");
    if (e == NULL)
    {
        cout << "ENGINE_by_id failed" << endl;
        cout<<ERR_error_string(ERR_get_error(),NULL)<<endl;
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

    if (!EVP_MD_CTX_init(sign_context))
    {
        cout << "EVP_MD_CTX_init failed" << endl;
    }

    if (!EVP_DigestSignInit(sign_context, NULL, EVP_sha256(), NULL, privkey))
    {
        cout << "EVP_DigestSignInit failed" << endl;
    }

    if (!EVP_DigestSignUpdate(sign_context, data, strlen(data)))
    {
        cout << "EVP_DigestSignUpdate failed" << endl;
    }

    size_t sig_len = 0;
    if (!EVP_DigestSignFinal(sign_context, NULL, &sig_len))
    {
        cout << "EVP_DigestSignFinal failed" << endl;
    }

    if (sig_len <= 0)
    {
        cout << "sig_len <= 0" << endl;
    }

    unsigned char *sig_value = NULL;
    sig_value = (unsigned char *)OPENSSL_malloc(sig_len);
    if (sig_value == NULL)
    {
        cout << "OPENSSL_malloc failed" << endl;
    }

    if (!EVP_DigestSignFinal(sign_context, sig_value, &sig_len))
    {
        cout << "EVP_DigestSignFinal failed" << endl;
    }

    for (int i = 0; i < sig_len; i++)
    {
        cout << hex << (int)sig_value[i];
    }
    // const unsigned char *pubkey = ecdsa_pubkey;
    // EC_KEY *ec_pubkey = EC_KEY_new();
    // EC_KEY *res_pub = d2i_EC_PUBKEY(&ec_pubkey, &pubkey, sizeof(ecdsa_pubkey));
    // EVP_PKEY *pubkey = EVP_PKEY_new();
    // if(!EVP_PKEY_set1_EC_KEY(pubkey, res_pub)){
    //     cout<<"EVP_PKEY_set1_EC_KEY failed"<<endl;
    // }

    return 0;
}
