package com.lgypro.kms;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class AsymmetricEncryptionDecryption {
    public static void main(String[] args) {
        Region region = Region.AP_NORTHEAST_1;
        String keyId = "906d0359-e2a7-4cb5-971f-f6a7354721e3";
        String encryptionAlgorithm = "RSAES_OAEP_SHA_256";
        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            byte[] data = "hello world\n".getBytes(StandardCharsets.US_ASCII);
            SdkBytes encryptedData = encryptData(kmsClient, keyId, encryptionAlgorithm, data);
            System.out.println("After encryption: ");
            printHexString(encryptedData.asByteArray());
            byte[] decryptedData = decryptData(kmsClient, keyId, encryptionAlgorithm, encryptedData);
            System.out.println("After decryption: ");
            printHexString(decryptedData);
            System.out.println("is decryption correct? " + Arrays.equals(data, decryptedData));
            System.out.println("Done");
        }
    }

    public static SdkBytes encryptData(KmsClient kmsClient, String keyId, String encryptionAlgorithm, byte[] data) {
        try {
            SdkBytes myBytes = SdkBytes.fromByteArray(data);
            EncryptRequest encryptRequest = EncryptRequest.builder()
                    .keyId(keyId)
                    .plaintext(myBytes)
                    .encryptionAlgorithm(encryptionAlgorithm)
                    .build();

            EncryptResponse response = kmsClient.encrypt(encryptRequest);
            String algorithm = response.encryptionAlgorithm().toString();
            System.out.println("The encryption algorithm is " + algorithm);

            // Get the encrypted data.
            SdkBytes encryptedData = response.ciphertextBlob();
            return encryptedData;
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
        return null;
    }

    public static byte[] decryptData(KmsClient kmsClient, String keyId, String encryptionAlgorithm, SdkBytes encryptedData) {
        try {
            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(encryptedData)
                    .keyId(keyId)
                    .encryptionAlgorithm(encryptionAlgorithm)
                    .build();
            DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
            return decryptResponse.plaintext().asByteArray();
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return null;
        }
    }

    public static void printHexString(byte[] data) {
        int length = data.length;
        for (int i = 0; i < length; i++) {
            if ((i + 1) % 16 == 0) {
                System.out.printf("%02x%n", data[i]);
            } else {
                System.out.printf("%02x ", data[i]);
            }
        }
        System.out.println();
    }
}
