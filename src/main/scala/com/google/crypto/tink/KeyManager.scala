// Copyright 2017 Google Inc.
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
package com.google.crypto.tink

import com.google.crypto.tink.proto.{KeyData, KeyProto}
import com.google.protobuf.ByteString

import java.security.GeneralSecurityException

/**
 * A KeyManager "understands" keys of a specific key type: it can generate keys of the supported
 * type and create primitives for supported keys.
 *
 * <p>A key type is identified by the global name of the protocol buffer that holds the
 * corresponding key material, and is given by {@code typeUrl}-field of {@link KeyData}-protocol
 * buffer.
 *
 * <p>The template parameter {@code P} denotes the primitive corresponding to the keys handled by
 * this manager.
 *
 * @since 1.0.0
 */
trait KeyManager[P] {
  /**
   * Constructs an instance of P for the key given in {@code key}.
   *
   * <p>For primitives of type {@code Mac}, {@code Aead}, {@code PublicKeySign}, {@code
   * PublicKeyVerify}, {@code DeterministicAead}, {@code HybridEncrypt}, and {@code HybridDecrypt}
   * this should be a primitive which <b>ignores</b> the output prefix and assumes "RAW".
   *
   * @return the new constructed P
   * @throws GeneralSecurityException if the key given in {@code key} is corrupted or not supported
   */
  @throws[GeneralSecurityException]
  def getPrimitive(key: KeyProto): P

  /**
   * Generates a new key.
   *
   * @return the new generated key
   */
  @throws[GeneralSecurityException]
  def newKey: KeyProto

  /** @return true iff this KeyManager supports key type identified by {@code typeUrl}. */
  def doesSupport(typeUrl: String): Boolean

  /** @return the type URL that identifies the key type of keys managed by this KeyManager. */
  def getKeyType: String

  /**
   * Returns the primitive class object of the P. Should be implemented as {@code return P.class;}
   * when implementing a key manager for primitive {$code P}.
   *
   * @return {@code P.class}
   */
  def getPrimitiveClass: Class[P]

  /**
   * Generates a new {@code KeyData}.
   *
   * <p>This should be used solely by {@link KeysetManager}.
   *
   * @return the new generated key
   * @throws GeneralSecurityException if the specified format is wrong or not supported
   */
  // APIs for Key Management
  @throws[GeneralSecurityException]
  def newKeyData: KeyData
}