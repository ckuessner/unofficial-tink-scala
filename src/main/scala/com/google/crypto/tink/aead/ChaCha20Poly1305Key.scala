// Copyright 2023 Google LLC
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
package com.google.crypto.tink.aead

import com.google.crypto.tink.AccessesPartialKey
import com.google.crypto.tink.Key
import com.google.crypto.tink.annotations.Alpha
import com.google.crypto.tink.util.Bytes
import com.google.crypto.tink.util.SecretBytes
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.util.Objects

/**
 * Represents the Aead ChaCha20-Poly1305 specified in RFC 8439.
 *
 * <p>ChaCha20-Poly1305 allows no parameters; hence the main part here is really just the keys.
 * However, Tink allows prefixing every ciphertext with an ID-dependent prefix, see
 * [[ ChaCha20Poly1305Parameters.Variant]].
 */
@Alpha object ChaCha20Poly1305Key {
  private def getOutputPrefix(parameters: ChaCha20Poly1305Parameters, idRequirement: Option[Int]): Bytes = {
    if (parameters.getVariant eq ChaCha20Poly1305Parameters.Variant.NO_PREFIX) {
      return Bytes.copyFrom(Array.empty[Byte])
    }
    if (parameters.getVariant eq ChaCha20Poly1305Parameters.Variant.CRUNCHY) {
      return Bytes.copyFrom(ByteBuffer.allocate(5).put(0.toByte).putInt(idRequirement.get).array)
    }
    if (parameters.getVariant eq ChaCha20Poly1305Parameters.Variant.TINK) {
      return Bytes.copyFrom(ByteBuffer.allocate(5).put(1.toByte).putInt(idRequirement.get).array)
    }
    throw new IllegalStateException("Unknown Variant: " + parameters.getVariant)
  }

  //@RestrictedApi(
  //    explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
  //    link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
  //    allowedOnPath = ".*Test\\.java",
  //    allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  @throws[GeneralSecurityException]
  def create(secretBytes: SecretBytes): ChaCha20Poly1305Key = create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX, secretBytes, None)

  //@RestrictedApi(
  //    explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
  //    link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
  //    allowedOnPath = ".*Test\\.java",
  //    allowlistAnnotations = {AccessesPartialKey.class})
  @throws[GeneralSecurityException]
  def create(variant: ChaCha20Poly1305Parameters.Variant, secretBytes: SecretBytes, idRequirement: Option[Int]): ChaCha20Poly1305Key = {
    if ((variant ne ChaCha20Poly1305Parameters.Variant.NO_PREFIX) && (idRequirement == null || idRequirement.isEmpty)) {
      throw new GeneralSecurityException("For given Variant " + variant + " the value of idRequirement must be non-null")
    }
    if ((variant eq ChaCha20Poly1305Parameters.Variant.NO_PREFIX) && (idRequirement != null && idRequirement.isDefined)) {
      throw new GeneralSecurityException("For given Variant NO_PREFIX the value of idRequirement must be null")
    }
    if (secretBytes.size != 32) {
      throw new GeneralSecurityException("ChaCha20Poly1305 key must be constructed with key of length 32 bytes, not " + secretBytes.size)
    }
    val parameters = ChaCha20Poly1305Parameters.create(variant)
    new ChaCha20Poly1305Key(parameters, secretBytes, getOutputPrefix(parameters, idRequirement), if idRequirement == null then None else idRequirement)
  }

  @throws[GeneralSecurityException]
  def create(variant: ChaCha20Poly1305Parameters.Variant, secretBytes: SecretBytes, idRequirement: Int): ChaCha20Poly1305Key = {
    create(variant, secretBytes, Some(idRequirement))
  }
}

@Alpha final class ChaCha20Poly1305Key private(private val parameters: ChaCha20Poly1305Parameters,
                                               private val keyBytes: SecretBytes,
                                               private val outputPrefix: Bytes,
                                               private val idRequirement: Option[Int]) extends AeadKey {
  /*@Nullable*/ override def getOutputPrefix: Bytes = outputPrefix

  //@RestrictedApi(
  //    explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
  //    link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
  //    allowedOnPath = ".*Test\\.java",
  //    allowlistAnnotations = {AccessesPartialKey.class})
  def getKeyBytes: SecretBytes = keyBytes

  override def getParameters: ChaCha20Poly1305Parameters = parameters

  //@Nullable
  override def getIdRequirement: Option[Int] = idRequirement

  override def getIdRequirementOrNull: Integer = {
    val idRequirement = getIdRequirement
    if idRequirement.isEmpty then null else Int.box(idRequirement.get)
  }

  override def equalsKey(o: Key): Boolean = {
    if (!o.isInstanceOf[ChaCha20Poly1305Key]) return false
    val that = o.asInstanceOf[ChaCha20Poly1305Key]
    // Since outputPrefix is a function of parameters, we can ignore it here.
    that.parameters == parameters && that.keyBytes.equalsSecretBytes(keyBytes) && that.idRequirement == idRequirement
  }
}