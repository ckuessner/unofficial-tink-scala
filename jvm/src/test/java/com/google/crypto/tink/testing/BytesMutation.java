package com.google.crypto.tink.testing;

public class BytesMutation {
    public BytesMutation(byte[] value, String description) {
        this.value = value;
        this.description = description;
    }

    public byte[] value;
    public String description;
}
