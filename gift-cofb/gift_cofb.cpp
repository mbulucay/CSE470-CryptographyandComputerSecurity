#include "./include/aead.hpp"
#include "./include/utils.hpp"
#include <cassert>
#include <iostream>
#include <fstream>

using namespace gift_cofb_mbu;

int main()
{

  std::string text = 
  "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s,\
  when an unknown printer took a galley of type and scrambled it to make a type specimen book.\
  It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged.\
  It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages,\
  and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

  // key, nonce, tag, associated data, plain text, cipher text, decrypted text
  uint8_t key[16], nonce[16], tag[16];
  uint8_t data[32], txt[32], enc[32], dec[32];

  int s = 0;
  std::vector<std::string> blocks;
  while (s < text.size()) {
    blocks.push_back(text.substr(s, 32));
    s += 32;
  }

  random_data(key, sizeof(key));
  random_data(nonce, sizeof(nonce));
  random_data(txt, sizeof(txt));

  for(const auto& block : blocks){

    memcpy(data, block.c_str(), sizeof(data));
    encrypt(key, nonce, data, sizeof(data), txt, enc, sizeof(txt), tag);
    bool f = decrypt(key, nonce, tag, data, sizeof(data), enc, dec, sizeof(enc));

    std::cout << "GIFT-COFB AEAD" << std::endl << std::endl;
    std::cout << "Key       : " << to_hex(key, sizeof(key)) << std::endl;
    std::cout << "Nonce     : " << to_hex(nonce, sizeof(nonce)) << std::endl;
    std::cout << "Text      : " << to_hex(txt, sizeof(txt)) << std::endl;
    std::cout << "Encrypted : " << to_hex(enc, sizeof(enc)) << std::endl;
    std::cout << "Tag       : " << to_hex(tag, sizeof(tag)) << std::endl;
    std::cout << "Decrypted : " << to_hex(dec, sizeof(dec)) << std::endl;
  }

  return EXIT_SUCCESS;
}
