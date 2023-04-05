// Copyright 2020 Google LLC
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

package com.google.crypto.tink;

import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyProto;

import java.security.GeneralSecurityException;

/**
 * Implementation of the {@link KeyManager} interface based on an {@link KeyTypeManager}.
 *
 * <p>Choosing {@code PrimitiveT} equal to {@link java.lang.Void} is valid; in this case the
 * functions {@link #getPrimitive} will throw if invoked.
 */
@Alpha
class KeyManagerImpl<PrimitiveT, KeyProtoT extends KeyProto> implements KeyManager<PrimitiveT> {
  public KeyManagerImpl(
      KeyTypeManager<KeyProtoT> keyTypeManager, Class<PrimitiveT> primitiveClass) {
    if (!keyTypeManager.supportedPrimitives().contains(primitiveClass)
        && !Void.class.equals(primitiveClass)) {
      throw new IllegalArgumentException(
          String.format(
              "Given internalKeyMananger %s does not support primitive class %s",
              keyTypeManager.toString(), primitiveClass.getName()));
    }
    this.keyTypeManager = keyTypeManager;
    this.primitiveClass = primitiveClass;
  }

  private final KeyTypeManager<KeyProtoT> keyTypeManager;
  private final Class<PrimitiveT> primitiveClass;

  private static <CastedT> CastedT castOrThrowSecurityException(
      Object objectToCast, String exceptionText, Class<CastedT> classObject)
      throws GeneralSecurityException {
    if (!classObject.isInstance(objectToCast)) {
      throw new GeneralSecurityException(exceptionText);
    }
    @SuppressWarnings("unchecked")
    CastedT result = (CastedT) objectToCast;
    return result;
  }

  //@Override
  //public final PrimitiveT getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
  //  try {
  //    KeyProtoT keyProto = keyTypeManager.parseKey(serializedKey);
  //    return validateKeyAndGetPrimitive(keyProto);
  //  } catch (InvalidProtocolBufferException e) {
  //    throw new GeneralSecurityException(
  //        "Failures parsing proto of type " + keyTypeManager.getKeyClass().getName(), e);
  //  }
  //}

  @Override
  public final PrimitiveT getPrimitive(KeyProto key) throws GeneralSecurityException {
    return validateKeyAndGetPrimitive(
        castOrThrowSecurityException(
            key,
            "Expected proto of type " + keyTypeManager.getKeyClass().getName(),
            keyTypeManager.getKeyClass()));
  }

  //@Override
  //public final MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
  //  try {
  //    return keyFactoryHelper().parseValidateCreate(serializedKeyFormat);
  //  } catch (InvalidProtocolBufferException e) {
  //    throw new GeneralSecurityException(
  //        "Failures parsing proto of type "
  //            + keyTypeManager.keyFactory().getKeyFormatClass().getName(),
  //        e);
  //  }
  //}

  @Override
  public final KeyProto newKey() throws GeneralSecurityException {
    return keyFactoryHelper().validateCreate();
  }

  @Override
  public final boolean doesSupport(String typeUrl) {
    return typeUrl.equals(getKeyType());
  }

  @Override
  public final String getKeyType() {
    return keyTypeManager.getKeyType();
  }

  @Override
  public final KeyData newKeyData() throws GeneralSecurityException {
    KeyProtoT key = keyFactoryHelper().validateCreate();
    return KeyData.newBuilder()
        .setTypeUrl(getKeyType())
        .setValue(key)
        .setKeyMaterialType(keyTypeManager.keyMaterialType())
        .build();
  }

  @Override
  public final Class<PrimitiveT> getPrimitiveClass() {
    return primitiveClass;
  }

  private PrimitiveT validateKeyAndGetPrimitive(KeyProtoT keyProto)
      throws GeneralSecurityException {
    if (Void.class.equals(primitiveClass)) {
      throw new GeneralSecurityException("Cannot create a primitive for Void");
    }
    keyTypeManager.validateKey(keyProto);
    return keyTypeManager.getPrimitive(keyProto, primitiveClass);
  }

  /**
   * A helper class which exposes functions bundling multiple functions of the given {@link
   * KeyTypeManager.KeyFactory}.
   *
   * <p>The KeyFactory uses generics. By bundling functions in a class which uses the same generics
   * we can refer to the types in code.
   */
  private static class KeyFactoryHelper<KeyProtoT extends KeyProto> {
    KeyFactoryHelper(KeyTypeManager.KeyFactory<KeyProtoT> keyFactory) {
      this.keyFactory = keyFactory;
    }

    final KeyTypeManager.KeyFactory<KeyProtoT> keyFactory;

    private KeyProtoT validateCreate() throws GeneralSecurityException {
      return keyFactory.createKey();
    }

    //KeyProtoT parseValidateCreate(ByteString serializedKeyFormat)
    //    throws GeneralSecurityException, InvalidProtocolBufferException {
    //  return validateCreate(keyFactory.parseKeyFormat(serializedKeyFormat));
    //}

    //KeyProtoT castValidateCreate(KeyFormatProto keyFormat) throws GeneralSecurityException {
    //  return validateCreate(
    //      castOrThrowSecurityException(
    //          keyFormat,
    //          "Expected proto of type " + keyFactory.getKeyFormatClass().getName(),
    //          keyFactory.getKeyFormatClass()));
    //}
  }

  private KeyFactoryHelper<KeyProtoT> keyFactoryHelper() {
    return new KeyFactoryHelper<>(keyTypeManager.keyFactory());
  }
}
