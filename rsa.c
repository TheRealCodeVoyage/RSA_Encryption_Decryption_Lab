#include <stdio.h>
/* Using Big Number library provided by openssl*/
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM *a)
{
    /* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}
    int main()
    {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *m = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *n = BN_new();
        BIGNUM *d = BN_new();
        BIGNUM *enc = BN_new();
        BIGNUM *dec = BN_new();
        BIGNUM *enc_key = BN_new();
        BIGNUM *dec_key = BN_new();

        // Initialize e,n,d
        //e is used as public key
        //d is used as private key
        BN_hex2bn(&e, "010001");
        BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
        BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
        
        //Uncomment next line and Initialize plaintext m (in hex) if needed
        // BN_hex2bn(&m, "");
    
        //Uncomment next line and Initialize encrypted text (ciphertext) enc if needed
        //BN_hex2bn(&enc, "");

        //Encryption Formula: m^enc_key mod n

        //Uncomment next 3 lines and Initialize the encryption key based on the task
        //enc_key = ;
        //BN_mod_exp(enc,m,enc_key,n,ctx);
        //printBN("Encrypted message = ", enc);
    
        //Decryption Formula: enc^dec_key mod n

        //Uncomment next 3 lines andInitialize the decryption key based on the task
        //dec_key = ;
        //BN_mod_exp(dec,enc,dec_key,n,ctx);
        //printBN("Decrypted message = ", dec);

        return 0;
    }
