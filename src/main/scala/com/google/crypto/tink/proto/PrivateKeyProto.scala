package com.google.crypto.tink.proto

trait PrivateKeyProto extends KeyProto {

  def getPublicKey: PublicKeyProto

}
