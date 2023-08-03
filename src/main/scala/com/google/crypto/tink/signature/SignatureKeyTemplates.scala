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
package com.google.crypto.tink.signature

import com.google.crypto.tink.proto.{KeyTemplate, OutputPrefixType}

/**
 * Pre-generated {@link KeyTemplate} for {@link com.google.crypto.tink.PublicKeySign} and {@link
 * com.google.crypto.tink.PublicKeyVerify}.
 *
 * <p>We recommend to avoid this class in order to keep dependencies small.
 *
 * <ul>
 * <li>Using this class adds a dependency on protobuf. We hope that eventually it is possible to
 * use Tink without a dependency on protobuf.
 * <li>Using this class adds a dependency on classes for all involved key types.
 * </ul>
 *
 * These dependencies all come from static class member variables, which are initialized when the
 * class is loaded. This implies that static analysis and code minimization tools (such as proguard)
 * cannot remove the usages either.
 *
 * <p>Instead, we recommend to use {@code KeysetHandle.generateEntryFromParametersName} or {@code
 * KeysetHandle.generateEntryFromParameters}.
 *
 * <p>One can use these templates to generate new {@link com.google.crypto.tink.proto.Keyset} with
 * {@link com.google.crypto.tink.KeysetHandle}. To generate a new keyset that contains a single
 * {@code EcdsaPrivateKey}, one can do:
 *
 * <pre>{@code
 * Config.register(SignatureConfig.TINK_1_1_0);
 * KeysetHandle handle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
 * PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);
 * PublicKeyVerify verifier = handle.getPublicKeyset().getPrimitive(PublicKeyVerify.class);
 * }</pre>
 *
 * @since 1.0.0
 */
object SignatureKeyTemplates {
  /**
   * A {@link KeyTemplate} that generates new instances of {@link
 * com.google.crypto.tink.proto.Ed25519PrivateKey}.
   *
   * @since 1.1.0
   */
  val ED25519: KeyTemplate = KeyTemplate.newBuilder.setTypeUrl(new Ed25519PrivateKeyManager().getKeyType).setOutputPrefixType(OutputPrefixType.TINK).build
  /**
   * A {@link KeyTemplate} that generates new instances of {@link
 * com.google.crypto.tink.proto.ED25519PrivateKey}.
   *
   * The difference between {@link ED25519WithRawOutput} and {@link ED25519} is the format of
   * signatures generated. {@link ED25519WithRawOutput} generates signatures of
   * {@link OutputPrefixType.RAW} format, which is 64 bytes long.
   *
   * @since 1.3.0
   */
  val ED25519WithRawOutput: KeyTemplate = KeyTemplate.newBuilder.setTypeUrl(new Ed25519PrivateKeyManager().getKeyType).setOutputPrefixType(OutputPrefixType.RAW).build
}