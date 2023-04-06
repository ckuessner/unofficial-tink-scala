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
import com.google.crypto.tink.internal.PrivateKeyTypeManager;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyProto;
import com.google.crypto.tink.proto.PublicKeyProto;

import java.security.GeneralSecurityException;

/**
 * Implementation of the {@link PrivateKeyManager} interface based on an {@link
 * PrivateKeyTypeManager} and the corresponding public key manager, implemented by an {@link
 * KeyTypeManager}.
 *
 * <p>Choosing {@code PrimitiveT} equal to {@link java.lang.Void} is valid; in this case the
 * functions {@link #getPrimitive} will throw if invoked.
 */
@Alpha
class PrivateKeyManagerImpl<
        PrimitiveT, KeyProtoT extends KeyProto, PublicKeyProtoT extends PublicKeyProto>
    extends KeyManagerImpl<PrimitiveT, KeyProtoT> implements PrivateKeyManager<PrimitiveT> {

  private final PrivateKeyTypeManager<KeyProtoT, PublicKeyProtoT> privateKeyManager;
  private final KeyTypeManager<PublicKeyProtoT> publicKeyManager;

  public PrivateKeyManagerImpl(
      PrivateKeyTypeManager<KeyProtoT, PublicKeyProtoT> privateKeyManager,
      KeyTypeManager<PublicKeyProtoT> publicKeyManager,
      Class<PrimitiveT> primitiveClass) {
    super(privateKeyManager, primitiveClass);
    this.privateKeyManager = privateKeyManager;
    this.publicKeyManager = publicKeyManager;
  }

  @Override
  public KeyData getPublicKeyData(KeyProto keyProto) throws GeneralSecurityException {
    if (keyProto == null) throw new NullPointerException();

    // TODO: Refactor this
    KeyProtoT privKeyProto;
    try {
      privKeyProto = (KeyProtoT) keyProto;
    } catch (ClassCastException e) {
      throw new GeneralSecurityException("Cannot get a validated public key from a " + keyProto.getClass() + " using a " + getClass());
    }

    privateKeyManager.validateKey(privKeyProto);
    PublicKeyProtoT publicKeyProto = privateKeyManager.getPublicKey(privKeyProto);
    publicKeyManager.validateKey(publicKeyProto);
    return KeyData.newBuilder()
        .setTypeUrl(publicKeyManager.getKeyType())
        .setValue(publicKeyProto)
        .setKeyMaterialType(publicKeyManager.keyMaterialType())
        .build();
  }
}
