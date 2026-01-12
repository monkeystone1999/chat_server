#include "../inc/crypt_service.h"
#include "../inc/user_service.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------
// [설정 상]
// --------------------------------------------------------
#define AES_KEY_LEN 32 // 256 bits
#define GCM_IV_LEN 12  // 96 bits (Standard for GCM)
#define GCM_TAG_LEN 16 // 128 bits (Authentication Tag)

// --------------------------------------------------------
// [유틸리티] Base64 인코딩/디코딩 (OpenSSL BIO 사용)
// 직접 구현보다 OpenSSL 내장을 쓰는 것이 안전하고 빠릅니다.
// --------------------------------------------------------

// 바이너리 -> Base64 문자열
char *base64_encode(const unsigned char *input, int length) {
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 한 줄로 출력
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);

  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length + 1);
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = 0;

  BIO_free_all(b64);
  return buff;
}

// Base64 문자열 -> 바이너리
unsigned char *base64_decode(const char *input, int *out_len) {
  BIO *b64, *bmem;
  size_t len = strlen(input);
  unsigned char *buffer = (unsigned char *)malloc(len); // 넉넉하게 할당
  memset(buffer, 0, len);

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf((void *)input, len);
  bmem = BIO_push(b64, bmem);

  *out_len = BIO_read(bmem, buffer, len);
  BIO_free_all(bmem);

  return buffer;
}

// --------------------------------------------------------
// [함수 1] AES-256-GCM 암호화 (EVP API 사용)
// 리턴: 암호문 길이, 실패 시 -1
// --------------------------------------------------------
int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext, unsigned char *tag) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  // 1. Context 생성
  if (!(ctx = EVP_CIPHER_CTX_new()))
    return -1;

  // 2. 초기화 (AES-256-GCM)
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    return -1;

  // 3. Key, IV 설정
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    return -1;

  // 4. 암호화 수행
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    return -1;
  ciphertext_len = len;

  // 5. 마무리 (GCM은 여기서 패딩 처리가 없으므로 0이 나옴)
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    return -1;
  ciphertext_len += len;

  // 6. 인증 태그(Tag) 추출
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag))
    return -1;

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

// --------------------------------------------------------
// [함수 2] AES-256-GCM 복호화
// 리턴: 평문 길이, 실패(위변조 포함) 시 -1
// --------------------------------------------------------
int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *tag, const unsigned char *key,
                    const unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    return -1;

  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    return -1;
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    return -1;

  // 복호화 수행
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    return -1;
  plaintext_len = len;

  // ★ 중요: 복호화 마무리 전 Tag 설정 (GCM 검증을 위해 필수)
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag))
    return -1;

  // 마무리 및 검증 (Tag가 틀리면 여기서 0 반환)
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  EVP_CIPHER_CTX_free(ctx);

  if (ret > 0) {
    plaintext_len += len;
    return plaintext_len;
  } else {
    return -1; // 검증 실패
  }
}

// --------------------------------------------------------
// [함수 3] RSA-4096 공개키로 AES 키 암호화 (Key Encapsulation)
// --------------------------------------------------------
unsigned char *rsa_encrypt_key(EVP_PKEY *pubkey, const unsigned char *aes_key,
                               size_t *out_len) {
  EVP_PKEY_CTX *ctx;
  unsigned char *encrypted_key = NULL;

  ctx = EVP_PKEY_CTX_new(pubkey, NULL);
  if (!ctx)
    return NULL;

  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    return NULL;

  // RSA Padding 설정 (OAEP 권장)
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    return NULL;

  // 1. 길이 측정
  if (EVP_PKEY_encrypt(ctx, NULL, out_len, aes_key, AES_KEY_LEN) <= 0)
    return NULL;

  encrypted_key = (unsigned char *)malloc(*out_len);

  // 2. 실제 암호화
  if (EVP_PKEY_encrypt(ctx, encrypted_key, out_len, aes_key, AES_KEY_LEN) <=
      0) {
    free(encrypted_key);
    return NULL;
  }

  EVP_PKEY_CTX_free(ctx);
  return encrypted_key;
}

// --------------------------------------------------------
// [함수 4] RSA-4096 개인키로 AES 키 복호화
// --------------------------------------------------------
unsigned char *rsa_decrypt_key(EVP_PKEY *privkey, const unsigned char *enc_key,
                               size_t enc_len) {
  EVP_PKEY_CTX *ctx;
  unsigned char *decrypted_key = NULL;
  size_t out_len;

  ctx = EVP_PKEY_CTX_new(privkey, NULL);
  if (!ctx)
    return NULL;

  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    return NULL;
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    return NULL;

  // 길이 측정
  if (EVP_PKEY_decrypt(ctx, NULL, &out_len, enc_key, enc_len) <= 0)
    return NULL;

  decrypted_key = (unsigned char *)malloc(out_len);

  // 복호화
  if (EVP_PKEY_decrypt(ctx, decrypted_key, &out_len, enc_key, enc_len) <= 0) {
    free(decrypted_key);
    return NULL;
  }

  // 검증: AES 키 길이와 일치하는지
  if (out_len != AES_KEY_LEN) {
    free(decrypted_key);
    return NULL;
  }

  EVP_PKEY_CTX_free(ctx);
  return decrypted_key;
}

// ========================================================
// [메인 로직] Client -> Server 시뮬레이션
// ========================================================
int main() {
  // 0. (사전준비) RSA 키쌍 생성 (실제론 파일에서 로드함)
  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(pctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 4096);
  EVP_PKEY_keygen(pctx, &pkey); // pkey에 개인키/공개키 모두 포함됨
  EVP_PKEY_CTX_free(pctx);

  printf("[Init] RSA-4096 Key Pair generated.\n\n");

  /* -----------------------------------------------------
     [CLIENT SIDE]
     1. 랜덤 AES 키/IV 생성
     2. 데이터 암호화 (AES)
     3. AES 키 암호화 (RSA)
     4. Base64 인코딩 -> 전송
  ----------------------------------------------------- */
  unsigned char aes_key[AES_KEY_LEN];
  unsigned char iv[GCM_IV_LEN];
  RAND_bytes(aes_key, AES_KEY_LEN);
  RAND_bytes(iv, GCM_IV_LEN);

  const char *msg = "This is a Top Secret message.";
  unsigned char ciphertext[1024];
  unsigned char tag[GCM_TAG_LEN];

  // AES 암호화
  int cipher_len = aes_gcm_encrypt((unsigned char *)msg, strlen(msg), aes_key,
                                   iv, ciphertext, tag);

  // RSA로 AES 키 암호화 (Enveloped Key)
  size_t enc_key_len;
  unsigned char *enc_key_bin = rsa_encrypt_key(pkey, aes_key, &enc_key_len);

  // Base64 인코딩 (전송용 문자열 생성)
  char *b64_enc_key = base64_encode(enc_key_bin, enc_key_len);
  char *b64_iv = base64_encode(iv, GCM_IV_LEN);
  char *b64_tag = base64_encode(tag, GCM_TAG_LEN);
  char *b64_cipher = base64_encode(ciphertext, cipher_len);

  // -- 클라이언트는 이 문자열들을 JSON으로 묶어 서버에 보냄 --
  printf("--- [Client Sends] ---\n");
  printf("Encrypted Key (B64): %s... (truncated)\n",
         b64_enc_key); // 너무 기니까
  printf("IV (B64): %s\n", b64_iv);
  printf("Tag (B64): %s\n", b64_tag);
  printf("Ciphertext (B64): %s\n\n", b64_cipher);

  // 보안: 사용한 AES 키 메모리 삭제
  OPENSSL_cleanse(aes_key, AES_KEY_LEN);
  free(enc_key_bin);

  /* -----------------------------------------------------
     [SERVER SIDE]
     1. Base64 디코딩
     2. AES 키 복호화 (RSA)
     3. 데이터 복호화 및 검증 (AES-GCM)
  ----------------------------------------------------- */
  int dec_iv_len, dec_tag_len, dec_cipher_len;
  int dec_key_bin_len; // Base64 decode length (not used for RSA decrypt param
                       // directly but needed for buffer)

  // Base64 디코딩
  unsigned char *srv_enc_key = base64_decode(b64_enc_key, &dec_key_bin_len);
  unsigned char *srv_iv = base64_decode(b64_iv, &dec_iv_len);
  unsigned char *srv_tag = base64_decode(b64_tag, &dec_tag_len);
  unsigned char *srv_cipher = base64_decode(b64_cipher, &dec_cipher_len);

  // RSA 복호화 -> AES 키 획득
  unsigned char *srv_aes_key =
      rsa_decrypt_key(pkey, srv_enc_key, dec_key_bin_len);
  if (!srv_aes_key) {
    fprintf(stderr, "Server: Failed to decrypt AES key.\n");
    return 1;
  }

  // AES-GCM 복호화
  unsigned char plaintext[1024];
  int plain_len = aes_gcm_decrypt(srv_cipher, dec_cipher_len, srv_tag,
                                  srv_aes_key, srv_iv, plaintext);

  printf("--- [Server Receives] ---\n");
  if (plain_len >= 0) {
    plaintext[plain_len] = '\0';
    printf("Decryption Success!\nMessage: %s\n", plaintext);
  } else {
    printf("Decryption Failed! (Tag mismatch or corrupted data)\n");
  }

  // [Cleanup]
  OPENSSL_cleanse(srv_aes_key, AES_KEY_LEN);
  free(srv_aes_key);
  free(srv_enc_key);
  free(srv_iv);
  free(srv_tag);
  free(srv_cipher);
  free(b64_enc_key);
  free(b64_iv);
  free(b64_tag);
  free(b64_cipher);
  EVP_PKEY_free(pkey);

  return 0;
}
