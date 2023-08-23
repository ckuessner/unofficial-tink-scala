package com.google.crypto.tink.subtle

import org.bouncycastle.crypto.digests.SHA512Digest

object EngineFactory {
  def sha512MessageDigestInstance: SHA512Digest = new SHA512Digest()
}
