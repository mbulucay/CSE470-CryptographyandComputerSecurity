#pragma once
#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <immintrin.h>


namespace gift {

struct state_t
{
  uint32_t cipher[4];
  uint16_t key[8];
};

const size_t ROUNDS = 40;

const uint32_t B7 = 0b10000000u;
const uint32_t B6 = 0b01000000u;
const uint32_t B5 = 0b00100000u;
const uint32_t B4 = 0b00010000u;
const uint32_t B3 = 0b00001000u;
const uint32_t B2 = 0b00000100u;
const uint32_t B1 = 0b00000010u;
const uint32_t B0 = 0b00000001u;

const uint32_t BIT_PERM_S3[32] = { 3, 7, 11, 15, 19, 23, 27, 31, 2, 6, 10, 14, 18, 22, 26, 30, 1, 5, 9,  13, 17, 21, 25, 29, 0, 4, 8,  12, 16, 20, 24, 28 };
const uint32_t BIT_PERM_S2[32] = { 2, 6, 10, 14, 18, 22, 26, 30, 1, 5, 9,  13, 17, 21, 25, 29, 0, 4, 8,  12, 16, 20, 24, 28, 3, 7, 11, 15, 19, 23, 27, 31 };
const uint32_t BIT_PERM_S1[32] = { 1, 5, 9,  13, 17, 21, 25, 29, 0, 4, 8,  12, 16, 20, 24, 28, 3, 7, 11, 15, 19, 23, 27, 31, 2, 6, 10, 14, 18, 22, 26, 30 };
const uint32_t BIT_PERM_S0[32] = { 0, 4, 8,  12, 16, 20, 24, 28, 3, 7, 11, 15, 19, 23, 27, 31, 2, 6, 10, 14, 18, 22, 26, 30, 1, 5, 9,  13, 17, 21, 25, 29 };

const uint8_t RC[ROUNDS] = {
  0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
  0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
  0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
  0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
};


void initialize(state_t* const __restrict stateOf, const uint8_t* const __restrict text, const uint8_t* const __restrict key  
)
{
  for (size_t i = 0; i < 4; i++) {
    const size_t boff = i << 2;

    stateOf->cipher[i] = (static_cast<uint32_t>(text[boff ^ 0]) << 24) | (static_cast<uint32_t>(text[boff ^ 1]) << 16) | (static_cast<uint32_t>(text[boff ^ 2]) << 8) | (static_cast<uint32_t>(text[boff ^ 3]) << 0);
  }

  for (size_t i = 0; i < 8; i++) {
    const size_t boff = i << 1;

    stateOf->key[i] = (static_cast<uint16_t>(key[boff ^ 0]) << 8) | (static_cast<uint16_t>(key[boff ^ 1]) << 0);
  }
}

void initialize(state_t* const __restrict stateOf, const uint32_t* const __restrict text, const uint8_t* const __restrict key )
{
  std::memcpy(stateOf->cipher, text, 16);

  for (size_t i = 0; i < 8; i++) {
    const size_t boff = i << 1;

    stateOf->key[i] = (static_cast<uint16_t>(key[boff ^ 0]) << 8) |
                 (static_cast<uint16_t>(key[boff ^ 1]) << 0);
  }
}

void sub_cells(state_t* const stateOf)
{
  const uint32_t t0 = stateOf->cipher[0] & stateOf->cipher[2];
  stateOf->cipher[1] ^= t0;

  const uint32_t t1 = stateOf->cipher[1] & stateOf->cipher[3];
  stateOf->cipher[0] ^= t1;

  const uint32_t t2 = stateOf->cipher[0] | stateOf->cipher[1];
  stateOf->cipher[2] ^= t2;

  stateOf->cipher[3] ^= stateOf->cipher[2];
  stateOf->cipher[1] ^= stateOf->cipher[3];
  stateOf->cipher[3] = ~stateOf->cipher[3];

  const uint32_t t3 = stateOf->cipher[0] & stateOf->cipher[1];
  stateOf->cipher[2] ^= t3;

  std::swap(stateOf->cipher[0], stateOf->cipher[3]);
}

void perm_bits(state_t* const stateOf)
{

  uint32_t b7arr[]{ B7, B7, B7, B7 };
  uint32_t b6arr[]{ B6, B6, B6, B6 };
  uint32_t b5arr[]{ B5, B5, B5, B5 };
  uint32_t b4arr[]{ B4, B4, B4, B4 };
  uint32_t b3arr[]{ B3, B3, B3, B3 };
  uint32_t b2arr[]{ B2, B2, B2, B2 };
  uint32_t b1arr[]{ B1, B1, B1, B1 };
  uint32_t b0arr[]{ B0, B0, B0, B0 };

  const __m128i b7vec = _mm_load_si128((__m128i*)b7arr);
  const __m128i b6vec = _mm_load_si128((__m128i*)b6arr);
  const __m128i b5vec = _mm_load_si128((__m128i*)b5arr);
  const __m128i b4vec = _mm_load_si128((__m128i*)b4arr);
  const __m128i b3vec = _mm_load_si128((__m128i*)b3arr);
  const __m128i b2vec = _mm_load_si128((__m128i*)b2arr);
  const __m128i b1vec = _mm_load_si128((__m128i*)b1arr);
  const __m128i b0vec = _mm_load_si128((__m128i*)b0arr);

  const __m128i s = _mm_load_si128((__m128i*)stateOf->cipher);

  const __m128i sa = _mm_xor_si128(
    _mm_xor_si128(
      _mm_xor_si128(
        _mm_xor_si128(
          _mm_xor_si128(
            _mm_xor_si128(
              _mm_xor_si128(_mm_and_si128(_mm_srli_epi32(s, 21), b7vec),
                            _mm_and_si128(_mm_srli_epi32(s, 18), b6vec)),
              _mm_and_si128(_mm_srli_epi32(s, 15), b5vec)),
            _mm_and_si128(_mm_srli_epi32(s, 12), b4vec)),
          _mm_and_si128(_mm_srli_epi32(s, 9), b3vec)),
        _mm_and_si128(_mm_srli_epi32(s, 6), b2vec)),
      _mm_and_si128(_mm_srli_epi32(s, 3), b1vec)),
    _mm_and_si128(_mm_srli_epi32(s, 0), b0vec));

  const __m128i sb = _mm_xor_si128(
    _mm_xor_si128(
      _mm_xor_si128(
        _mm_xor_si128(
          _mm_xor_si128(
            _mm_xor_si128(
              _mm_xor_si128(_mm_and_si128(_mm_srli_epi32(s, 22), b7vec),
                            _mm_and_si128(_mm_srli_epi32(s, 19), b6vec)),
              _mm_and_si128(_mm_srli_epi32(s, 16), b5vec)),
            _mm_and_si128(_mm_srli_epi32(s, 13), b4vec)),
          _mm_and_si128(_mm_srli_epi32(s, 10), b3vec)),
        _mm_and_si128(_mm_srli_epi32(s, 7), b2vec)),
      _mm_and_si128(_mm_srli_epi32(s, 4), b1vec)),
    _mm_and_si128(_mm_srli_epi32(s, 1), b0vec));

  const __m128i sc = _mm_xor_si128(
    _mm_xor_si128(
      _mm_xor_si128(
        _mm_xor_si128(
          _mm_xor_si128(
            _mm_xor_si128(
              _mm_xor_si128(_mm_and_si128(_mm_srli_epi32(s, 23), b7vec),
                            _mm_and_si128(_mm_srli_epi32(s, 20), b6vec)),
              _mm_and_si128(_mm_srli_epi32(s, 17), b5vec)),
            _mm_and_si128(_mm_srli_epi32(s, 14), b4vec)),
          _mm_and_si128(_mm_srli_epi32(s, 11), b3vec)),
        _mm_and_si128(_mm_srli_epi32(s, 8), b2vec)),
      _mm_and_si128(_mm_srli_epi32(s, 5), b1vec)),
    _mm_and_si128(_mm_srli_epi32(s, 2), b0vec));

  const __m128i sd = _mm_xor_si128(
    _mm_xor_si128(
      _mm_xor_si128(
        _mm_xor_si128(
          _mm_xor_si128(
            _mm_xor_si128(
              _mm_xor_si128(_mm_and_si128(_mm_srli_epi32(s, 24), b7vec),
                            _mm_and_si128(_mm_srli_epi32(s, 21), b6vec)),
              _mm_and_si128(_mm_srli_epi32(s, 18), b5vec)),
            _mm_and_si128(_mm_srli_epi32(s, 15), b4vec)),
          _mm_and_si128(_mm_srli_epi32(s, 12), b3vec)),
        _mm_and_si128(_mm_srli_epi32(s, 9), b2vec)),
      _mm_and_si128(_mm_srli_epi32(s, 6), b1vec)),
    _mm_and_si128(_mm_srli_epi32(s, 3), b0vec));

  uint32_t sa_[4]{};
  uint32_t sb_[4]{};
  uint32_t sc_[4]{};
  uint32_t sd_[4]{};

  _mm_store_si128((__m128i*)sa_, sa);
  _mm_store_si128((__m128i*)sb_, sb);
  _mm_store_si128((__m128i*)sc_, sc);
  _mm_store_si128((__m128i*)sd_, sd);

  stateOf->cipher[0] = (sb_[0] << 24) ^ (sc_[0] << 16) ^ (sd_[0] << 8) ^ sa_[0];
  stateOf->cipher[1] = (sc_[1] << 24) ^ (sd_[1] << 16) ^ (sa_[1] << 8) ^ sb_[1];
  stateOf->cipher[2] = (sd_[2] << 24) ^ (sa_[2] << 16) ^ (sb_[2] << 8) ^ sc_[2];
  stateOf->cipher[3] = (sa_[3] << 24) ^ (sb_[3] << 16) ^ (sc_[3] << 8) ^ sd_[3];


  const uint32_t s0 = stateOf->cipher[0];
  const uint32_t s1 = stateOf->cipher[1];
  const uint32_t s2 = stateOf->cipher[2];
  const uint32_t s3 = stateOf->cipher[3];

  // subtutaion box
  const uint32_t s0b0 = ((s0 >> 21) & B7) ^ ((s0 >> 18) & B6) ^ ((s0 >> 15) & B5) ^ ((s0 >> 12) & B4) ^ ((s0 >> 9) & B3) ^ ((s0 >> 6) & B2) ^ ((s0 >> 3) & B1) ^ ((s0 >> 0) & B0);
  const uint32_t s1b1 = ((s1 >> 21) & B7) ^ ((s1 >> 18) & B6) ^ ((s1 >> 15) & B5) ^ ((s1 >> 12) & B4) ^ ((s1 >> 9) & B3) ^ ((s1 >> 6) & B2) ^ ((s1 >> 3) & B1) ^ ((s1 >> 0) & B0);
  const uint32_t s1b0 = ((s1 >> 22) & B7) ^ ((s1 >> 19) & B6) ^ ((s1 >> 16) & B5) ^ ((s1 >> 13) & B4) ^ ((s1 >> 10) & B3) ^ ((s1 >> 7) & B2) ^ ((s1 >> 4) & B1) ^ ((s1 >> 1) & B0);
  const uint32_t s2b1 = ((s2 >> 22) & B7) ^ ((s2 >> 19) & B6) ^ ((s2 >> 16) & B5) ^ ((s2 >> 13) & B4) ^ ((s2 >> 10) & B3) ^ ((s2 >> 7) & B2) ^ ((s2 >> 4) & B1) ^ ((s2 >> 1) & B0);
  const uint32_t s2b0 = ((s2 >> 23) & B7) ^ ((s2 >> 20) & B6) ^ ((s2 >> 17) & B5) ^ ((s2 >> 14) & B4) ^ ((s2 >> 11) & B3) ^ ((s2 >> 8) & B2) ^ ((s2 >> 5) & B1) ^ ((s2 >> 2) & B0);
  const uint32_t s3b1 = ((s3 >> 23) & B7) ^ ((s3 >> 20) & B6) ^ ((s3 >> 17) & B5) ^ ((s3 >> 14) & B4) ^ ((s3 >> 11) & B3) ^ ((s3 >> 8) & B2) ^ ((s3 >> 5) & B1) ^ ((s3 >> 2) & B0);
  const uint32_t s3b0 = ((s3 >> 24) & B7) ^ ((s3 >> 21) & B6) ^ ((s3 >> 18) & B5) ^ ((s3 >> 15) & B4) ^ ((s3 >> 12) & B3) ^ ((s3 >> 9) & B2) ^ ((s3 >> 6) & B1) ^ ((s3 >> 3) & B0);
  const uint32_t s0b1 = ((s0 >> 24) & B7) ^ ((s0 >> 21) & B6) ^ ((s0 >> 18) & B5) ^ ((s0 >> 15) & B4) ^ ((s0 >> 12) & B3) ^ ((s0 >> 9) & B2) ^ ((s0 >> 6) & B1) ^ ((s0 >> 3) & B0);
  const uint32_t s0b2 = ((s0 >> 23) & B7) ^ ((s0 >> 20) & B6) ^ ((s0 >> 17) & B5) ^ ((s0 >> 14) & B4) ^ ((s0 >> 11) & B3) ^ ((s0 >> 8) & B2) ^ ((s0 >> 5) & B1) ^ ((s0 >> 2) & B0);
  const uint32_t s1b3 = ((s1 >> 23) & B7) ^ ((s1 >> 20) & B6) ^ ((s1 >> 17) & B5) ^ ((s1 >> 14) & B4) ^ ((s1 >> 11) & B3) ^ ((s1 >> 8) & B2) ^ ((s1 >> 5) & B1) ^ ((s1 >> 2) & B0);
  const uint32_t s1b2 = ((s1 >> 24) & B7) ^ ((s1 >> 21) & B6) ^ ((s1 >> 18) & B5) ^ ((s1 >> 15) & B4) ^ ((s1 >> 12) & B3) ^ ((s1 >> 9) & B2) ^ ((s1 >> 6) & B1) ^ ((s1 >> 3) & B0);
  const uint32_t s2b3 = ((s2 >> 24) & B7) ^ ((s2 >> 21) & B6) ^ ((s2 >> 18) & B5) ^ ((s2 >> 15) & B4) ^ ((s2 >> 12) & B3) ^ ((s2 >> 9) & B2) ^ ((s2 >> 6) & B1) ^ ((s2 >> 3) & B0);
  const uint32_t s2b2 = ((s2 >> 21) & B7) ^ ((s2 >> 18) & B6) ^ ((s2 >> 15) & B5) ^ ((s2 >> 12) & B4) ^ ((s2 >> 9) & B3) ^ ((s2 >> 6) & B2) ^ ((s2 >> 3) & B1) ^ ((s2 >> 0) & B0);
  const uint32_t s3b3 = ((s3 >> 21) & B7) ^ ((s3 >> 18) & B6) ^ ((s3 >> 15) & B5) ^ ((s3 >> 12) & B4) ^ ((s3 >> 9) & B3) ^ ((s3 >> 6) & B2) ^ ((s3 >> 3) & B1) ^ ((s3 >> 0) & B0);
  const uint32_t s3b2 = ((s3 >> 22) & B7) ^ ((s3 >> 19) & B6) ^ ((s3 >> 16) & B5) ^ ((s3 >> 13) & B4) ^ ((s3 >> 10) & B3) ^ ((s3 >> 7) & B2) ^ ((s3 >> 4) & B1) ^ ((s3 >> 1) & B0);
  const uint32_t s0b3 = ((s0 >> 22) & B7) ^ ((s0 >> 19) & B6) ^ ((s0 >> 16) & B5) ^ ((s0 >> 13) & B4) ^ ((s0 >> 10) & B3) ^ ((s0 >> 7) & B2) ^ ((s0 >> 4) & B1) ^ ((s0 >> 1) & B0);

  stateOf->cipher[0] = (s0b3 << 24) ^ (s0b2 << 16) ^ (s0b1 << 8) ^ s0b0;
  stateOf->cipher[1] = (s1b3 << 24) ^ (s1b2 << 16) ^ (s1b1 << 8) ^ s1b0;
  stateOf->cipher[2] = (s2b3 << 24) ^ (s2b2 << 16) ^ (s2b1 << 8) ^ s2b0;
  stateOf->cipher[3] = (s3b3 << 24) ^ (s3b2 << 16) ^ (s3b1 << 8) ^ s3b0;

}

void add_round_keys(state_t* const stateOf, const size_t r_idx)
{
  const uint32_t u = (static_cast<uint32_t>(stateOf->key[2]) << 16) | (static_cast<uint32_t>(stateOf->key[3]) << 0);
  const uint32_t v = (static_cast<uint32_t>(stateOf->key[6]) << 16) | (static_cast<uint32_t>(stateOf->key[7]) << 0);

  stateOf->cipher[2] ^= u;
  stateOf->cipher[1] ^= v;

  stateOf->cipher[3] ^= (1u << 31) | static_cast<uint32_t>(RC[r_idx]);
}

void update_key_state(state_t* const stateOf)
{
  const uint16_t t0 = std::rotr(stateOf->key[6], 2);
  const uint16_t t1 = std::rotr(stateOf->key[7], 12);

  uint16_t tmp[6];
  std::memcpy(tmp, stateOf->key, sizeof(tmp));
  std::memcpy(stateOf->key + 2, tmp, sizeof(tmp));

  stateOf->key[0] = t0;
  stateOf->key[1] = t1;
}

void round(state_t* const stateOf, const size_t r_idx)
{
  sub_cells(stateOf);
  perm_bits(stateOf);
  add_round_keys(stateOf, r_idx);

  update_key_state(stateOf);
}

template<const size_t R>
void permute(state_t* const stateOf)
{
  for (size_t i = 0; i < R; i++) {
    round(stateOf, i);
  }
}

}
