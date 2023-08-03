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

import com.google.crypto.tink.proto.OutputPrefixType
import com.google.crypto.tink.subtle.Bytes
import com.google.crypto.tink.{CryptoFormat, PrimitiveSet, PrimitiveWrapper, PublicKeyVerify, Registry}

import java.security.GeneralSecurityException
import java.util
import java.util.logging.Logger

/**
 * The implementation of {@code PrimitiveWrapper<DeterministicAead>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To verify a signature,
 * the primitive uses the prefix of the signature to efficiently select the right key in the set. If
 * there is no key associated with the prefix or if the keys associated with the prefix do not work,
 * the primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType# RAW}.
 *
 * @since 1.0.0
 */
object PublicKeyVerifyWrapper {
  private val logger = Logger.getLogger(classOf[PublicKeyVerifyWrapper].getName)
  private val FORMAT_VERSION = Array[Byte](0)
  private val WRAPPER = new PublicKeyVerifyWrapper

  private class WrappedPublicKeyVerify(private val primitives: PrimitiveSet[PublicKeyVerify]) //private final MonitoringClient.Logger monitoringLogger;
    extends PublicKeyVerify {
    @throws[GeneralSecurityException]
    override def verify(signature: Array[Byte], data: Array[Byte]): Unit = {
      if (signature.length <= CryptoFormat.NON_RAW_PREFIX_SIZE) {
        // This also rejects raw signatures with size of 4 bytes or fewer. We're not aware of any
        // schemes that output signatures that small.
        //monitoringLogger.logFailure();
        throw new GeneralSecurityException("signature too short")
      }
      val prefix = util.Arrays.copyOf(signature, CryptoFormat.NON_RAW_PREFIX_SIZE)
      val sigNoPrefix = util.Arrays.copyOfRange(signature, CryptoFormat.NON_RAW_PREFIX_SIZE, signature.length)
      var entries = primitives.getPrimitive(prefix)

      if entries.exists { entry =>
        var data2 = data
        if (entry.getOutputPrefixType == OutputPrefixType.LEGACY) data2 = Bytes.concat(data2, FORMAT_VERSION)

        try {
          entry.getPrimitive.verify(sigNoPrefix, data2)
          // If there is no exception, the signature is valid and we can return.
          true
        } catch {
          // Ignored as we want to continue verification with the remaining keys.
          case e: GeneralSecurityException =>
            logger.info("signature prefix matches a key, but cannot verify: " + e)
            false
        }
      } then return;

      // None "non-raw" key matched, so let's try the raw keys (if any exist).
      entries = primitives.getRawPrimitives
      if entries.exists(entry => try {
        entry.getPrimitive.verify(signature, data)
        //monitoringLogger.log(entry.getKeyId(), data.length);
        // If there is no exception, the signature is valid and we can return.
        true
      } catch {
        case e: GeneralSecurityException =>
          // Ignored as we want to continue verification with raw keys.
          false
      }) then return;

      // nothing works.
      throw new GeneralSecurityException("invalid signature")
    }
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link PublicKeyVerify}
   * argument.
   */
  @throws[GeneralSecurityException]
  def register(): Unit = {
    Registry.registerPrimitiveWrapper(WRAPPER)
  }
}

class PublicKeyVerifyWrapper extends PrimitiveWrapper[PublicKeyVerify, PublicKeyVerify] {
  override def wrap(primitives: PrimitiveSet[PublicKeyVerify]) = new PublicKeyVerifyWrapper.WrappedPublicKeyVerify(primitives)

  override def getPrimitiveClass: Class[PublicKeyVerify] = classOf[PublicKeyVerify]

  override def getInputPrimitiveClass: Class[PublicKeyVerify] = classOf[PublicKeyVerify]
}