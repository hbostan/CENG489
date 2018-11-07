#include <openssl/evp.h>
#include <string.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <vector>

uint8_t iv[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                  0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

uint8_t mykey[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

void print_hex(uint8_t* buf, int a) {
  for (int i = 0; i < a; i++) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}

void print_hex(std::vector<uint8_t> buf) {
  for (auto byte : buf) {
    printf("%02x", byte);
  }
  printf("\n");
}

int ReadFileBytes(char const* filename, uint8_t*& result) {
  std::ifstream input_stream(filename, std::ios::binary | std::ios::ate);
  std::ifstream::pos_type pos = input_stream.tellg();
  printf("%d\n", pos);
  result = new uint8_t[pos];
  input_stream.seekg(0, std::ios::beg);
  input_stream.read(reinterpret_cast<char*>(result), pos);
  return pos;
}

void ReadDictionary(std::vector<std::string>& dictionary) {
  std::ifstream input_stream("words.txt");
  std::string word;
  while (input_stream >> word) {
    dictionary.push_back(word);
  }
}

int Encrypt(uint8_t* p, int p_len, uint8_t* key, uint8_t* iv,
            uint8_t* ciphertext) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  int len, c_len;
  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext, &len, p, p_len);
  c_len = len;
  if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    printf("error");
  }
  c_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return c_len;
}

int main() {
  uint8_t* plaintext = 0;
  uint8_t* ciphertext = 0;
  std::vector<std::string> dict;
  int p_len = ReadFileBytes("plaintext.txt", plaintext);
  int c_len = ReadFileBytes("ciphertext", ciphertext);
  printf("%x %x\n", plaintext, ciphertext);
  ReadDictionary(dict);
  print_hex(plaintext, p_len);
  print_hex(ciphertext, c_len);
  for (auto word : dict) {
    uint8_t key[16];
    uint8_t encrypted[c_len];
    for (int i = 0; i < 16; i++) {
      key[i] = i < word.length() ? word[i] : 0;
    }
    for (int i = 0; i < c_len; i++) {
      encrypted[i] = 0;
    }
    int a = Encrypt(plaintext, p_len, key, iv, encrypted);
    if (encrypted[0] == ciphertext[0] && encrypted[1] == ciphertext[1] &&
        encrypted[5] == ciphertext[5]) {
      print_hex(encrypted, a);
      print_hex(ciphertext, a);
      std::cout << word << std::endl;
    }
  }
  return 0;
}
