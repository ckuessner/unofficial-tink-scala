// Copyright 2022 Google LLC
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

package com.google.crypto.tink.internal;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters;
import com.google.crypto.tink.aead.ChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;

import java.security.GeneralSecurityException;

/**
 * Represents a {@code Parameters} object serialized with binary protobuf Serialization.
 *
 * <p>{@code ProtoParametersSerialization} objects fully describe a {@code Parameters} object, but
 * tailored for protocol buffer serialization.
 */
//@Immutable
public final class ProtoParametersSerialization implements Serialization {
  private final Bytes objectIdentifier;
  private final KeyTemplate keyTemplate;

  private ProtoParametersSerialization(KeyTemplate keyTemplate) {
    this.keyTemplate = keyTemplate;
    this.objectIdentifier = toBytesFromPrintableAscii(keyTemplate.getTypeUrl());
  }

  public Parameters toParametersPojo() throws GeneralSecurityException {
    var outputPrefixType = keyTemplate.getOutputPrefixType();
    if ("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key".equals(keyTemplate.getTypeUrl())) {
      XChaCha20Poly1305Parameters.Variant variant = XChaCha20Poly1305ProtoSerialization.toVariant(outputPrefixType);
      return XChaCha20Poly1305Parameters.create(variant);
    } else if ("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key".equals(keyTemplate.getTypeUrl())) {
      ChaCha20Poly1305Parameters.Variant variant = ChaCha20Poly1305ProtoSerialization.toVariant(outputPrefixType);
      return ChaCha20Poly1305Parameters.create(variant);
    } else {
      throw new GeneralSecurityException("Cannot create parameters POJO for " + keyTemplate.getTypeUrl());
    }
  }

  /** Creates a new {@code ProtoParametersSerialization} object from the individual parts. */
  public static ProtoParametersSerialization create(
      String typeUrl, OutputPrefixType outputPrefixType) {
    return create(
        KeyTemplate.newBuilder()
            .setTypeUrl(typeUrl)
            .setOutputPrefixType(outputPrefixType)
            .build());
  }

  /** Creates a new {@code ProtoParametersSerialization} object. */
  public static ProtoParametersSerialization create(KeyTemplate keyTemplate) {
    return new ProtoParametersSerialization(keyTemplate);
  }

  /** The contents of the field value in the message com.google.crypto.tink.proto.KeyData. */
  public KeyTemplate getKeyTemplate() {
    return keyTemplate;
  }

  /** The typeUrl. */
  @Override
  public Bytes getObjectIdentifier() {
    return objectIdentifier;
  }
}
