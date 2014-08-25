package com.bejibx.encryption;

public class Main {

    public static void printByteArrayAsHex(byte[] array)
    {
        StringBuilder s = new StringBuilder();
        for (byte b : array)
        {
            s.append(String.format("0x%02X ", b));
            s.append(" ");
        }
        System.out.println(s.toString());
    }

    public static void main(String[] args) {
        byte[] plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff};
        byte[] key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        AriaCipher cipher = new AriaCipher(key);
        byte[] ciphertext = cipher.encrypt(plaintext);
        printByteArrayAsHex(ciphertext);
        ciphertext = cipher.decrypt(ciphertext);
        printByteArrayAsHex(ciphertext);
    }
}
