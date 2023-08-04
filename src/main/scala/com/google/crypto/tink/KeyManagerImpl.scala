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
package com.google.crypto.tink

import com.google.crypto.tink.annotations.Alpha
import com.google.crypto.tink.internal.KeyTypeManager
import com.google.crypto.tink.proto.KeyData
import com.google.crypto.tink.proto.KeyProto
import java.security.GeneralSecurityException

/**
 * Implementation of the {@link KeyManager} interface based on an {@link KeyTypeManager}.
 *
 * <p>Choosing {@code PrimitiveT} equal to {@link java.lang.Void} is valid; in this case the
 * functions {@link # getPrimitive} will throw if invoked.
 */
@Alpha object KeyManagerImpl {
  @throws[GeneralSecurityException]
  private def castOrThrowSecurityException[CastedT](objectToCast: AnyRef, exceptionText: String, classObject: Class[CastedT]) = {
    if (!classObject.isInstance(objectToCast)) throw new GeneralSecurityException(exceptionText)
    @SuppressWarnings(Array("unchecked")) val result = objectToCast.asInstanceOf[CastedT]
    result
  }

  /**
   * A helper class which exposes functions bundling multiple functions of the given {@link
 * KeyTypeManager.KeyFactory}.
   *
   * <p>The KeyFactory uses generics. By bundling functions in a class which uses the same generics
   * we can refer to the types in code.
   */
  private[tink] class KeyFactoryHelper[KeyProtoT <: KeyProto] (private[tink] val keyFactory: KeyTypeManager.KeyFactory[KeyProtoT]) {
    @throws[GeneralSecurityException]
    private[KeyManagerImpl] def validateCreate = keyFactory.createKey
  }
}

@Alpha
class KeyManagerImpl[PrimitiveT, KeyProtoT <: KeyProto](private val keyTypeManager: KeyTypeManager[KeyProtoT],
                                                        private val primitiveClass: Class[PrimitiveT]
                                                       ) extends KeyManager[PrimitiveT] {

  if (!keyTypeManager.supportedPrimitives.contains(primitiveClass) && !(classOf[Void] == primitiveClass)) {
    throw new IllegalArgumentException(String.format("Given internalKeyMananger %s does not support primitive class %s", keyTypeManager.toString, primitiveClass.getName))
  }

  @throws[GeneralSecurityException]
  override final def getPrimitive(key: KeyProto): PrimitiveT = validateKeyAndGetPrimitive(KeyManagerImpl.castOrThrowSecurityException(key, "Expected proto of type " + keyTypeManager.getKeyClass.getName, keyTypeManager.getKeyClass))

  @throws[GeneralSecurityException]
  override final def newKey: KeyProto = keyFactoryHelper.validateCreate

  override final def doesSupport(typeUrl: String): Boolean = typeUrl == getKeyType

  override final def getKeyType: String = keyTypeManager.getKeyType

  @throws[GeneralSecurityException]
  override final def newKeyData: KeyData = {
    val key = keyFactoryHelper.validateCreate
    KeyData.newBuilder.setTypeUrl(getKeyType).setValue(key).setKeyMaterialType(keyTypeManager.keyMaterialType).build
  }

  override final def getPrimitiveClass: Class[PrimitiveT] = primitiveClass

  @throws[GeneralSecurityException]
  private def validateKeyAndGetPrimitive(keyProto: KeyProtoT) = {
    if (classOf[Void] == primitiveClass) throw new GeneralSecurityException("Cannot create a primitive for Void")
    keyTypeManager.validateKey(keyProto)
    keyTypeManager.getPrimitive(keyProto, primitiveClass)
  }

  private def keyFactoryHelper = new KeyManagerImpl.KeyFactoryHelper[KeyProtoT](keyTypeManager.keyFactory)
}