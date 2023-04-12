// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.aead.internal

import com.google.crypto.tink.subtle.Bytes

import java.nio.{ByteBuffer, ByteOrder}
import java.security.{GeneralSecurityException, InvalidKeyException}

/**
 * Abstract base class for {@link InsecureNonceChaCha20}.
 *
 * <p>ChaCha20 and XChaCha20 have two differences: the size of the nonce and the initial state of
 * the block function that produces a key stream block from a key, a nonce, and a counter.
 *
 * <p>Concrete implementations of this class are meant to be used to construct an
 * {@link com.google.crypto.tink.Aead} with {@link com.google.crypto.tink.subtle.Poly1305}.
 *
 * <p>Since this class supports user-supplied nonces, which would be insecure if the nonce ever
 * repeates, most users should not use this class directly.
 */
private[internal] abstract class InsecureNonceChaCha20Base @throws[InvalidKeyException] (keyBytes: Array[Byte], private val initialCounter: Int) {

  if (keyBytes.length != ChaCha20Util.KEY_SIZE_IN_BYTES) {
    throw new InvalidKeyException("The key length in bytes must be 32.")
  }

  private[internal] val key: Array[Int] = ChaCha20Util.toIntArray(keyBytes)

  /** Returns the initial state from {@code nonce} and {@code counter}. */
  private[internal] def createInitialState(nonce: Array[Int], counter: Int): Array[Int]

  /**
   * The size of the randomly generated nonces.
   *
   * <p>ChaCha20 uses 12-byte nonces, but XChaCha20 use 24-byte nonces.
   */
  private[internal] def nonceSizeInBytes: Int

  /** Encrypts {@code plaintext} using {@code nonce}. */
  @throws[GeneralSecurityException]
  def encrypt(nonce: Array[Byte], plaintext: Array[Byte]): Array[Byte] = {
    val ciphertext = ByteBuffer.allocate(plaintext.length)
    encrypt(ciphertext, nonce, plaintext)
    ciphertext.array
  }

  /** Encrypts {@code plaintext} using {@code nonce} and writes result to {@code output}. */
  @throws[GeneralSecurityException]
  def encrypt(output: ByteBuffer, nonce: Array[Byte], plaintext: Array[Byte]): Unit = {
    if (output.remaining < plaintext.length) throw new IllegalArgumentException("Given ByteBuffer output is too small")
    process(nonce, output, ByteBuffer.wrap(plaintext))
  }

  /** Decrypts {@code ciphertext} using {@code nonce}. */
  @throws[GeneralSecurityException]
  def decrypt(nonce: Array[Byte], ciphertext: Array[Byte]): Array[Byte] = decrypt(nonce, ByteBuffer.wrap(ciphertext))

  /** Decrypts {@code ciphertext} using {@code nonce}. */
  @throws[GeneralSecurityException]
  def decrypt(nonce: Array[Byte], ciphertext: ByteBuffer): Array[Byte] = {
    val plaintext = ByteBuffer.allocate(ciphertext.remaining)
    process(nonce, plaintext, ciphertext)
    plaintext.array
  }

  @throws[GeneralSecurityException]
  private def process(nonce: Array[Byte], output: ByteBuffer, input: ByteBuffer): Unit = {
    if (nonce.length != nonceSizeInBytes) throw new GeneralSecurityException("The nonce length (in bytes) must be " + nonceSizeInBytes)
    val length = input.remaining
    val numBlocks = (length / ChaCha20Util.BLOCK_SIZE_IN_BYTES) + 1
    for (i <- 0 until numBlocks) {
      val keyStreamBlock = chacha20Block(nonce, i + initialCounter)
      if (i == numBlocks - 1) {
        // last block
        Bytes.xor(output, input, keyStreamBlock, length % ChaCha20Util.BLOCK_SIZE_IN_BYTES)
      }
      else Bytes.xor(output, input, keyStreamBlock, ChaCha20Util.BLOCK_SIZE_IN_BYTES)
    }
  }

  // https://tools.ietf.org/html/rfc8439#section-2.3.
  private[internal] def chacha20Block(nonce: Array[Byte], counter: Int) = {
    val state = createInitialState(ChaCha20Util.toIntArray(nonce), counter)
    val workingState = state.clone
    ChaCha20Util.shuffleState(workingState)
    for (i <- state.indices) {
      state(i) += workingState(i)
    }
    val out = ByteBuffer.allocate(ChaCha20Util.BLOCK_SIZE_IN_BYTES).order(ByteOrder.LITTLE_ENDIAN)
    out.asIntBuffer.put(state, 0, ChaCha20Util.BLOCK_SIZE_IN_INTS)
    out
  }
}