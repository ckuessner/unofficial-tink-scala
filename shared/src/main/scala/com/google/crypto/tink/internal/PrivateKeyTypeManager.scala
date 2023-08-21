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
package com.google.crypto.tink.internal

import com.google.crypto.tink.annotations.Alpha
import com.google.crypto.tink.proto.{KeyProto, PublicKeyProto}

import java.security.GeneralSecurityException

/**
 * A PrivateKeyManager is like an {@link KeyTypeManager}, but additionally has a method to create a
 * public key.
 */
@Alpha
abstract class PrivateKeyTypeManager[KeyProtoT <: KeyProto, PublicKeyProtoT <: PublicKeyProto] @SafeVarargs protected(clazz: Class[KeyProtoT],
                                                                                                                      private val publicKeyClazz: Class[PublicKeyProtoT],
                                                                                                                      _factories: PrimitiveFactory[_, KeyProtoT]*
                                                                                                                     ) extends KeyTypeManager[KeyProtoT](clazz, _factories : _*) {
  /** Returns the class corresponding to the public key protobuffer. */
  final def getPublicKeyClass: Class[PublicKeyProtoT] = publicKeyClazz

  /** Creates a public key from the given private key. */
  @throws[GeneralSecurityException]
  def getPublicKey(keyProto: KeyProtoT): PublicKeyProtoT
}