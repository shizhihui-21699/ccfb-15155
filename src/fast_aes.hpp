// Fast, allocation-free AES block encryption used to decide whether an
// arbitrary window of memory could be a key for a known ciphertext sample.
//
// Rationale: a raw key sitting in a buffer has no structure to recognise, so
// the only honest detector is the ciphertext itself.  For CBC with a known IV
// and a guessed plaintext prefix (file magic), correctness of a candidate key K
// is exactly
//        E_K(P0 xor IV) == C0
// which costs one key expansion and one block encryption.  That turns "is this
// window a key?" into a ~100 ns question and lets the scanner sweep every
// 16-byte-aligned window of a multi-gigabyte image without false positives.
#pragma once
#include <cstdint>
#include <cstddef>

namespace kh {

// Expand key (16/24/32 bytes) into round keys and encrypt one block.
// `out` receives 16 ciphertext bytes.
void aes_encrypt_block(const uint8_t* key, size_t keylen, const uint8_t in[16], uint8_t out[16]);

// Same, for decryption (needed for ECB/CBC-from-ciphertext tests).
void aes_decrypt_block(const uint8_t* key, size_t keylen, const uint8_t in[16], uint8_t out[16]);

// Bulk path for the key sweep: expand the key once, then run several probe
// blocks.  `in_blocks` holds n*16 bytes; `out_blocks` receives n*16 bytes.
struct AesCtx;
void aes_encrypt_many(const uint8_t* key, size_t keylen, const uint8_t* in, size_t n,
                      uint8_t* out);
void aes_decrypt_many(const uint8_t* key, size_t keylen, const uint8_t* in, size_t n,
                      uint8_t* out);

// Sweep helper: one key expansion serving both directions.
void aes_mixed_many(const uint8_t* key, size_t keylen,
                    const uint8_t* const* dec_in, size_t ndec, uint8_t* dec_out,
                    const uint8_t* const* enc_in, size_t nenc, uint8_t* enc_out);

}  // namespace kh
