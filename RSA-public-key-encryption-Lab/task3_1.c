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
  BIGNUM *p      = BN_new();
  BIGNUM *p1      = BN_new();
  BIGNUM *q      = BN_new();
  BIGNUM *q1      = BN_new();
  BIGNUM *e      = BN_new();
  BIGNUM *d      = BN_new();
  BIGNUM *temp   = BN_new();
  BIGNUM *temp1   = BN_new();
  BIGNUM *n   = BN_new();
  BIGNUM *n1   = BN_new();
  BIGNUM *res = BN_new();
  
  // Initialize p, q, n
  // BN_hex2bn(&a, "2A3B4C55FF77889AED3F");
  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  printBN("p = ", p); 
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  printBN("q = ", q); 
  BN_hex2bn(&e, "0D88C3");
  BN_dec2bn(&temp1, "1");

  // compute n = p*q 
  BN_mul(n, p, q, ctx); 
  printBN("p * q = ", n); 
  BN_sub(p1, p, temp1);  
  printBN("p1 = ", p1); 
  BN_sub(q1, q, temp1);  
  printBN("q1 = ", q1); 
  BN_mul(n1, p1, q1, ctx); 
  printBN("p1 * q1 = ", n1); 
  // e*d mod ((p-1)(q-1)) = 1
  BN_mod_inverse(d, e, n1, ctx);   
  printBN("d = ", d);
  return 0;
}
