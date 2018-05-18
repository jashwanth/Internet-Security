#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<openssl/evp.h>

void pad_with_spaces(char* singleword, int len) {
  int curlen = strlen(singleword);
  while (curlen < len) {
    singleword[curlen] = ' ';
    curlen++;
  }
  singleword[len] = '\0';
}
     
/*One problem I found out is that we need to pass unsigned char *buf (not char *buf) because 
otherwise each character is considered signed and hex digits are mostly printed as fffff... */
void print_result_output_file(char singleword[], unsigned char *buf, int len, FILE* outputList) {
   for (int i = 0; i < 16; i++) {
     fprintf(outputList, "%c", singleword[i]);
   }
   /* Add a space between key and encrypted string */
   fprintf(outputList, "%c", ' ');
   for (int i = 0; i < len; i++) {
     fprintf(outputList, "%02x", buf[i]);
   }
   /* Add an end of file for each pair of key and encrypted string */
   fprintf(outputList, "%c", '\n');
}

int main() {
  int encryptp = 1;
  // use aes-128-cbc to generate ciphertext from plaintext
  unsigned char key[] = "00112233445566778899aabbccddeeff";
  //unsigned char iv[] = "0102030405060708";
  unsigned char iv[16] = {0}; //"0000000000000000" ; // "0102030405060708";
  /* for (int i = 0; i < 16; i++) {
       iv[i] = 0x00;
     } */
  /* Don't set key or IV right away ; we want to check lengths */ 
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx); 
  EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, encryptp);

  OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
  OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);
  
  FILE *wordsList, *outputList;
  wordsList =  fopen("words.txt", "r");
  outputList = fopen("output_encrypted.txt", "a+");
  if (wordsList < 0) {
    perror("Error ");
  } 
  char inptext[] = "This is a top secret.";
//  printf("Plain string is: %s and length = %d\n", inptext, strlen(inptext));
  char ciphertext[] = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";
//  printf("Cipher string is: %s and length = %d\n", ciphertext, strlen(ciphertext));
  FILE* output;
  unsigned char singleword[16];
  int count = 0;
  int templen = 0;
  unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
//  memset(&outbuf, 0, sizeof(outbuf));
  int outlen, tmplen;
//  printf("Before While Plain string is: %s and length = %d\n", inptext, strlen(inptext));
  while ((fgets(singleword, 16, wordsList) != NULL) ) {
   count++;
   /* Since the words.txt ends with \n for each line, we replace that '\n' with '\0' to end that string */
   singleword[strlen(singleword)-1] = '\0';
//   printf("Len of string is %d\n", strlen(singleword));
   if (strlen(singleword) < 16) {
     pad_with_spaces(singleword, 16);
   }
   for(int i = 0; i < strlen(inptext); i++) {
      printf("%c ", inptext[i]);
   }
//    printf("\nBefore EncryptInit String is %s , len of inptext is %d\n",inptext, strlen(inptext));
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, singleword, iv); 
//    printf("String is %s , len of inptext is %d\n",inptext, strlen(inptext));
// Here I am hardcoding the inptext string. need to debug why when inptext is given as 
//  input it is producing outlen as zero 
    if (!EVP_CipherUpdate(&ctx, outbuf, &outlen, "This is a top secret.", 21)) {
  //  if (!EVP_EncryptUpdate(&ctx, outbuf, &outlen, inptext, strlen(inptext))) {
      /* Error */
      EVP_CIPHER_CTX_cleanup(&ctx);
      return 0;
    }
//    printf("Outlen Before final is %d\n", outlen);
    /* Clean up any last bytes left in the output buffer */
    if (!EVP_CipherFinal_ex(&ctx, outbuf+outlen, &templen)) { 
 //   if (!EVP_EncryptFinal_ex(&ctx, outbuf+outlen, &templen)) {
       /* Error */
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }
//    printf("Outlen is %d\n", outlen);
//    printf("templen is %d\n", templen);
    outlen += templen;
    /* We create double the size of outbuf because for every character
      in outbuf we have 2 hexadecimal characters in buf_hex_encrypt */
    char buf_hex_encrypt[2*outlen + 1];
     char *buf_operate = buf_hex_encrypt;
    for (int i = 0; i < outlen; i++) {
      buf_operate += sprintf(buf_operate, "%02x",outbuf[i]);
    } 
    /* End the string with \0 value */
    *(buf_operate+1) = '\0';
//    printf("Key is %s\n", singleword);
//    printf("Outlen is %d\n", outlen);
     if (strcmp(buf_hex_encrypt, ciphertext) == 0 ) {
       printf("Found the secret key: %s\n", singleword);
     }
     print_result_output_file(singleword, outbuf, outlen, outputList);
     memset(singleword, 0, sizeof(singleword));
  }
/*  else  { }*/
  EVP_CIPHER_CTX_cleanup(&ctx);
  fclose(wordsList);
  fclose(outputList);
  //  perror("Closed successfully");
  return 0;
}
