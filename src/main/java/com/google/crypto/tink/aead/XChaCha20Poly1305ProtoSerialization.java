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

package com.google.crypto.tink.aead;

import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;

/**
 * Methods to serialize and parse {@link XChaCha20Poly1305Key} objects and {@link
 * XChaCha20Poly1305Parameters} objects
 */
@AccessesPartialKey
@SuppressWarnings("UnnecessarilyFullyQualified") // Fully specifying proto types is more readable
// TODO: change to more restrictive access modifier after conversion to scala
public final class XChaCha20Poly1305ProtoSerialization {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  private static final Bytes TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL);

  public static final KeySerializer<XChaCha20Poly1305Key, ProtoKeySerialization> KEY_SERIALIZER =
      KeySerializer.create(
          XChaCha20Poly1305ProtoSerialization::serializeKey,
          XChaCha20Poly1305Key.class,
          ProtoKeySerialization.class);

  public static final KeyParser<ProtoKeySerialization> KEY_PARSER =
      KeyParser.create(
          XChaCha20Poly1305ProtoSerialization::parseKey,
          TYPE_URL_BYTES,
          ProtoKeySerialization.class);

  private static OutputPrefixType toProtoOutputPrefixType(
      XChaCha20Poly1305Parameters.Variant variant) throws GeneralSecurityException {
    if (XChaCha20Poly1305Parameters.Variant.TINK.equals(variant)) {
      return OutputPrefixType.TINK;
    }
    if (XChaCha20Poly1305Parameters.Variant.CRUNCHY.equals(variant)) {
      return OutputPrefixType.CRUNCHY;
    }
    if (XChaCha20Poly1305Parameters.Variant.NO_PREFIX.equals(variant)) {
      return OutputPrefixType.RAW;
    }
    throw new GeneralSecurityException("Unable to serialize variant: " + variant);
  }

  public static XChaCha20Poly1305Parameters.Variant toVariant(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case TINK:
        return XChaCha20Poly1305Parameters.Variant.TINK;
        /** Parse LEGACY prefix to CRUNCHY, since they act the same for this type of key */
      case CRUNCHY:
      case LEGACY:
        return XChaCha20Poly1305Parameters.Variant.CRUNCHY;
      case RAW:
        return XChaCha20Poly1305Parameters.Variant.NO_PREFIX;
      default:
        throw new GeneralSecurityException(
            "Unable to parse OutputPrefixType: " + outputPrefixType);
    }
  }

  public static ProtoParametersSerialization serializeParameters(
      XChaCha20Poly1305Parameters parameters) throws GeneralSecurityException {
    return ProtoParametersSerialization.create(
        KeyTemplate.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setOutputPrefixType(toProtoOutputPrefixType(parameters.getVariant()))
            .build());
  }

  public static ProtoKeySerialization serializeKey(
      XChaCha20Poly1305Key key, /*@Nullable*/ SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        TYPE_URL,
        com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
            .setKeyValue(
                ByteString.copyFrom(
                    key.getKeyBytes().toByteArray(SecretKeyAccess.requireAccess(access))))
            .build(),
        KeyMaterialType.SYMMETRIC,
        toProtoOutputPrefixType(key.getParameters().getVariant()),
        key.getIdRequirementOrNull());
  }

  public static XChaCha20Poly1305Parameters parseParameters(
      ProtoParametersSerialization serialization) throws GeneralSecurityException {
    if (!serialization.getKeyTemplate().getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to XChaCha20Poly1305Parameters.parseParameters: "
              + serialization.getKeyTemplate().getTypeUrl());
    }
    return XChaCha20Poly1305Parameters.create(
        toVariant(serialization.getKeyTemplate().getOutputPrefixType()));
  }

  @SuppressWarnings("UnusedException")
  public static XChaCha20Poly1305Key parseKey(
      ProtoKeySerialization serialization, /*@Nullable*/ SecretKeyAccess access)
      throws GeneralSecurityException {
    if (!serialization.getTypeUrl().equals(TYPE_URL)) {
      throw new IllegalArgumentException(
          "Wrong type URL in call to XChaCha20Poly1305Parameters.parseParameters");
    }

    var value = serialization.getValue();
    if (value instanceof com.google.crypto.tink.proto.XChaCha20Poly1305Key) {
      com.google.crypto.tink.proto.XChaCha20Poly1305Key protoKey = (com.google.crypto.tink.proto.XChaCha20Poly1305Key) value;

      if (protoKey.getKeyValue() == null || protoKey.getKeyValue().size() != 32) {
        throw new GeneralSecurityException("Parsing XChaCha20Poly1305Key failed");
      }

      return XChaCha20Poly1305Key.create(
              toVariant(serialization.getOutputPrefixType()),
              SecretBytes.copyFrom(
                      protoKey.getKeyValue().toByteArray(), SecretKeyAccess.requireAccess(access)),
              serialization.getIdRequirementOrNull());
    } else {
      throw new GeneralSecurityException("Parsing XChaCha20Poly1305Key failed");
    }
  }

  private XChaCha20Poly1305ProtoSerialization() {}
}
