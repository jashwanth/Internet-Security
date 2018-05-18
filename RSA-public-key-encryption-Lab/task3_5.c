/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM *a)
{
   /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
    char* number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main()
{
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *e      = BN_new();
  BIGNUM *d      = BN_new();
  BIGNUM *n   = BN_new();
  BIGNUM *res = BN_new();
  BIGNUM *M = BN_new();
  BIGNUM *signature = BN_new();
  
  BN_hex2bn(&signature, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
  printBN("signature = ", signature);
  BN_hex2bn(&e, "010001");
  printBN("e = ", e); 
  BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
  printBN("n = ", n);
  // M^d mod n = signature.
  // signature^e mod n = Message
  BN_mod_exp(res, signature, e, n, ctx);
  printBN("Res = ", res);
  
  return 0;
}
