#include "mbedtls_engine.h"
#include <iostream>
#include <mbedtls/platform.h>
using namespace std;

int OpensslEcdsaEngine::ecdsa_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig,
                                   unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    cout << "mbedtls_ecdsa_sign" << endl;
    int ret = -1;
    unsigned char *key = NULL;
    char *pers = "ecdsa";
    int key_len = i2d_ECPrivateKey(eckey, NULL);
    if (!i2d_ECPrivateKey(eckey, &key))
    {
        cout << "i2d_ECPrivateKey failed" << endl;
        return 0;
    }

    if ((ret = mbedtls_ctr_drbg_seed(&ctx.ctr_drbg, mbedtls_entropy_func, &ctx.entropy, (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_printf(" failed! mbedtls_ctr_drbg_seed returned %d\n", ret);
        return 0;
    }

    if ((ret = mbedtls_pk_parse_key(&ctx.priv_key, ecdsa_privkey, sizeof(ecdsa_privkey), NULL, 0,
                                    mbedtls_ctr_drbg_random, &ctx.ctr_drbg)) != 0)
    {
        mbedtls_printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", (unsigned int)-ret);
        return 0;
    }

    unsigned char *buf = (unsigned char *)malloc(sizeof(unsigned char) * 80);
    if (buf == NULL)
    {
        cout << "malloc failed" << endl;
        return 0;
    }

    size_t len = 0;
    if ((ret = mbedtls_pk_sign(&ctx.priv_key, MBEDTLS_MD_SHA256, dgst, dlen, buf, 80, &len, mbedtls_ctr_drbg_random,
                               &ctx.ctr_drbg)) != 0)
    {
        mbedtls_printf(" failed! mbedtls_pk_sign returned -0x%04x\n", (unsigned int)-ret);
        return 0;
    }

    copy(buf, buf + len, sig);
    *siglen = len;

    return 1;
}

int OpensslEcdsaEngine::ecdsa_verify(int type, const unsigned char *dgst, int dgst_len, const unsigned char *sigbuf,
                                     int sig_len, EC_KEY *eckey)
{
    cout << "mbedtls_ecdsa_verify" << endl;
    int ret = -1;
    unsigned char *key = NULL;
    int key_len = i2d_ECPrivateKey(eckey, NULL);
    if ((ret = i2d_ECPrivateKey(eckey, &key)) != 1)
    {
        cout << "i2d_ECPrivateKey failed" << endl;
        return 0;
    }

    if ((ret = mbedtls_pk_parse_public_key(&ctx.pub_key, key, key_len)) != 0)
    {
        cout << "mbedtls_pk_parse_public_key failed" << endl;
        return 0;
    }

    if ((ret = mbedtls_pk_verify(&ctx.pub_key, MBEDTLS_MD_SHA256, dgst, dgst_len, sigbuf, sig_len)) != 0)
    {
        mbedtls_printf(" failed! mbedtls_pk_verify returned -0x%04x\n", (unsigned int)-ret);
        return 0;
    }
    return 1;
}

OpensslEcdsaEngine::OpensslEcdsaEngine()
{

    OpenSSL_add_all_algorithms();
    ec_key_method = EC_KEY_METHOD_new((EC_KEY_METHOD *)EC_KEY_OpenSSL());
    if (ec_key_method == NULL)
    {
        cout << "EC_KEY_METHOD_new failed" << endl;
    }

    EC_KEY_METHOD_set_sign(ec_key_method, ecdsa_sign, NULL, NULL);
    EC_KEY_METHOD_set_verify(ec_key_method, ecdsa_verify, NULL);
    engine = ENGINE_new();
    ENGINE_set_id(engine, "mbedtls");
    ENGINE_set_name(engine, "mbedtls_ecdsa");
    if (!ENGINE_set_EC(engine, ec_key_method))
    {
        cout << "ENGINE_set_EC failed" << endl;
    }
    if (!ENGINE_add(engine))
    {
        cout << "ENGINE_add failed" << endl;
    }
}

OpensslEcdsaEngine::~OpensslEcdsaEngine()
{
    EC_KEY_METHOD_free(ec_key_method);
    ENGINE_free(engine);
}

MbedtlsEcdsaCtx OpensslEcdsaEngine::ctx = MbedtlsEcdsaCtx();
