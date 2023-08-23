package javax.crypto

import java.security.GeneralSecurityException

class BadPaddingException(msg: String) extends GeneralSecurityException(msg) {
}
