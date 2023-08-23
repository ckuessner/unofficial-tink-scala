package java.security

/**
 * This Exception is missing in Scala.js but required for Tink
 */
class GeneralSecurityException(msg: String, cause: Throwable) extends Exception(msg, cause) {
  def this(msg: String) = this(msg, null)

  def this(cause: Throwable) = this(null, cause)
}