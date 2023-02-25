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

package com.google.crypto.tink.integration.android;

import android.util.Log;
import com.google.crypto.tink.Aead;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.ProviderException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * An {@link Aead} that does AES-GCM encryption with a key stored in <a
 * href="https://developer.android.com/training/articles/keystore.html">Android Keystore</a>.
 *
 * <p>This class requires Android M (API level 23) or newer.
 *
 * @since 1.0.0
 */
public final class AndroidKeystoreAesGcm implements Aead {
  private static final String TAG = AndroidKeystoreAesGcm.class.getSimpleName();
  private static final int MAX_WAIT_TIME_MILLISECONDS_BEFORE_RETRY = 100;
  // All instances of this class use a 12 byte IV and a 16 byte tag.
  private static final int IV_SIZE_IN_BYTES = 12;
  private static final int TAG_SIZE_IN_BYTES = 16;

  private final SecretKey key;

  public AndroidKeystoreAesGcm(String keyId) throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null /* param */);
    key = (SecretKey) keyStore.getKey(keyId, null /* password */);
    if (key == null) {
      throw new InvalidKeyException("Keystore cannot load the key with ID: " + keyId);
    }
  }

  /** This is for testing only */
  AndroidKeystoreAesGcm(String keyId, KeyStore keyStore) throws GeneralSecurityException {
    key = (SecretKey) keyStore.getKey(keyId, null /* password */);
    if (key == null) {
      throw new InvalidKeyException("Keystore cannot load the key with ID: " + keyId);
    }
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      return encryptInternal(plaintext, associatedData);
    } catch (ProviderException | GeneralSecurityException ex) {
      Log.w(TAG, "encountered a potentially transient KeyStore error, will wait and retry", ex);
      sleepRandomAmount();
      return encryptInternal(plaintext, associatedData);
    }
  }

  private byte[] encryptInternal(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    // Check that ciphertext is not longer than the max. size of a Java array.
    if (plaintext.length > Integer.MAX_VALUE - IV_SIZE_IN_BYTES - TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    byte[] ciphertext = new byte[IV_SIZE_IN_BYTES + plaintext.length + TAG_SIZE_IN_BYTES];
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    cipher.updateAAD(associatedData);
    int unusedWritten =
        cipher.doFinal(plaintext, 0, plaintext.length, ciphertext, IV_SIZE_IN_BYTES);
    // Copy the IV that is randomly generated by Android Keystore.
    System.arraycopy(cipher.getIV(), 0, ciphertext, 0, IV_SIZE_IN_BYTES);
    return ciphertext;
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext.length < IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    try {
      return decryptInternal(ciphertext, associatedData);
    } catch (AEADBadTagException ex) {
      throw ex;
    } catch (ProviderException | GeneralSecurityException ex) {
      Log.w(TAG, "encountered a potentially transient KeyStore error, will wait and retry", ex);
      sleepRandomAmount();
      return decryptInternal(ciphertext, associatedData);
    }
  }

  private byte[] decryptInternal(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    GCMParameterSpec params =
        new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, ciphertext, 0, IV_SIZE_IN_BYTES);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, key, params);
    cipher.updateAAD(associatedData);
    return cipher.doFinal(ciphertext, IV_SIZE_IN_BYTES, ciphertext.length - IV_SIZE_IN_BYTES);
  }

  private static void sleepRandomAmount() {
    int waitTimeMillis = (int) (Math.random() * MAX_WAIT_TIME_MILLISECONDS_BEFORE_RETRY);
    try {
      Thread.sleep(waitTimeMillis);
    } catch (InterruptedException ex) {
      // Ignored.
    }
  }
}
