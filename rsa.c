#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>

const char* pkLocation = "/home/cai/butler/rsa_pk.pem";
const char* skLocation = "/home/cai/butler/rsa_sk.pem";

typedef struct _Chars {
    unsigned char* data;
    size_t size;
} Chars;

void generate() {
    if (access(pkLocation, F_OK) == 0 && access(skLocation, F_OK) == 0) {
        return;
    }

    EVP_PKEY* keys = NULL;
    unsigned int bits = 2048, prime = 3;
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY_keygen_init(context);
    BIGNUM* big = BN_new();
    BN_set_word(big, prime);
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    params[1] = OSSL_PARAM_construct_uint("primes", &prime);
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(context, params);
    EVP_PKEY_generate(context, &keys);

    FILE* pkFile = fopen(pkLocation, "w");
    PEM_write_PUBKEY(pkFile, keys);
    fclose(pkFile);

    FILE* skFile = fopen(skLocation, "w");
    PEM_write_PrivateKey(skFile, keys, NULL, NULL, 0, NULL, NULL);
    fclose(skFile);

    BN_free(big);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(keys);

    return;
}

Chars read_all(const char* path) {
    Chars ret;
	FILE* file = fopen(path, "rb");
	fseek(file, 0, SEEK_END);
	ret.size = ftell(file);
	ret.data = (unsigned char*)malloc(ret.size * sizeof(unsigned char));
	rewind(file);
	fread(ret.data, sizeof(unsigned char), ret.size, file);
	fclose(file);
	return ret;
}

Chars get_pk() {
    return read_all(pkLocation);
}

Chars get_sk() {
    return read_all(skLocation);
}

Chars encrypt_once(Chars pk, Chars plainText) {
    Chars ret;

    BIO* pkBio = BIO_new_mem_buf(pk.data, pk.size);
    EVP_PKEY* key = EVP_PKEY_new();
    PEM_read_bio_PUBKEY(pkBio, &key, NULL, NULL);

    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(context);
    EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_encrypt(context, NULL, &ret.size, plainText.data, plainText.size);
    ret.data = (unsigned char*)malloc(ret.size * sizeof(unsigned char));
    EVP_PKEY_encrypt(context, ret.data, &ret.size, plainText.data, plainText.size);

    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(key);
    BIO_free_all(pkBio);

    return ret;
}

Chars concat(Chars a, Chars b) {
    Chars ret;
    if (a.size == 0) {
        return b;
    }
    if (b.size == 0) {
        return a;
    }
    ret.size = a.size + b.size;
    ret.data = (unsigned char*)malloc(ret.size * sizeof(unsigned char));
    memcpy(ret.data, a.data, a.size);
    memcpy(ret.data + a.size, b.data, b.size);

    free(a.data);
    free(b.data);
    
    return ret;
}

Chars mid(Chars chars, size_t pos, size_t len) {
    Chars ret;
    if (pos + len > chars.size) {
        len = chars.size - pos;
    }
    ret.data = chars.data + pos;
    ret.size = len;
    return ret;
}

Chars encrypt(Chars pk, Chars plainText) {
    Chars ret;
    ret.size = 0;
    size_t unit = 128;
    size_t left = 0;
    do {
        ret = concat(ret, encrypt_once(pk, mid(plainText, left, unit)));
        left += unit;
    } while (left < plainText.size);
    return ret;
}

Chars decrypt_once(Chars sk, Chars cipherText) {
    Chars ret;

    BIO* skBio = BIO_new_mem_buf(sk.data, sk.size);
    EVP_PKEY* key = EVP_PKEY_new();
    PEM_read_bio_PrivateKey(skBio, &key, NULL, NULL);

    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_decrypt_init(context);
    EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_decrypt(context, NULL, &ret.size, cipherText.data, cipherText.size);
    ret.data = (unsigned char*)malloc(ret.size * sizeof(unsigned char));
    EVP_PKEY_decrypt(context, ret.data, &ret.size, cipherText.data, cipherText.size);

    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(key);
    BIO_free_all(skBio);

    return ret;
}

Chars decrypt(Chars sk, Chars cipherText) {
    Chars ret;
    ret.size = 0;
    size_t unit = 256;
    size_t left = 0;
    do {
        ret = concat(ret, decrypt_once(sk, mid(cipherText, left, unit)));
        left += unit;
    } while (left < cipherText.size);
    return ret;
}

void free_chars(Chars chars) {
    free(chars.data);
    return;
}
