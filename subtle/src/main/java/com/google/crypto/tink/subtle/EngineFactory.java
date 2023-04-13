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

package com.google.crypto.tink.subtle;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * A factory that returns JCE engines, using pre-specified j.security.Providers.
 *
 * <p>This class contains a lot of static factories and static functions returning factories: these
 * allow customization and hide the typing complexity in this class. To use this class, import it,
 * and replace your <code>Cipher.getInstance(...)</code> with <code>
 * EngineFactory.CIPHER.getInstance(...)</code>.
 *
 * @since 1.0.0
 */
public final class EngineFactory<T_WRAPPER extends EngineWrapper<JcePrimitiveT>, JcePrimitiveT> {
  private final Policy<JcePrimitiveT> policy;

  /**
   * A Policy provides a wrapper around the JCE engines, and defines how a cipher instance will be
   * retrieved. A preferred list of providers can be passed, which the policy might use to
   * prioritize certain providers. For details see the specific policies.
   */
  private static interface Policy<JcePrimitiveT> {
    public JcePrimitiveT getInstance(String algorithm) throws GeneralSecurityException;
  }

  /**
   * The default policy, which uses the JDK priority for providers. If a list of preferred providers
   * is provided, then these will be used first in the order they are given.
   */
  private static class DefaultPolicy<JcePrimitiveT> implements Policy<JcePrimitiveT> {
    private DefaultPolicy(EngineWrapper<JcePrimitiveT> jceFactory) {
      this.jceFactory = jceFactory;
    }

    @Override
    public JcePrimitiveT getInstance(String algorithm) throws GeneralSecurityException {
      return this.jceFactory.getInstance(algorithm, null);
    }

    private final EngineWrapper<JcePrimitiveT> jceFactory;
  }

  public static final EngineFactory<EngineWrapper.TMessageDigest, MessageDigest> MESSAGE_DIGEST =
      new EngineFactory<>(new EngineWrapper.TMessageDigest());

  public EngineFactory(T_WRAPPER instanceBuilder) {
      policy = new DefaultPolicy<>(instanceBuilder);
  }

  public JcePrimitiveT getInstance(String algorithm) throws GeneralSecurityException {
    return policy.getInstance(algorithm);
  }
}
