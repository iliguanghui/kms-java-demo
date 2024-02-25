package com.lgypro.kms;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import java.util.Arrays;
import java.util.Map;

public class SymmetricEncryptionDecryption {
    public static void main(String[] args) {
        Region region = Region.AP_NORTHEAST_1;
        String keyId = "arn:aws:kms:ap-northeast-1:345164961032:key/7d0b4bb5-3ed7-45c6-bb1f-2dfd53a4cd47";
        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            byte[] data = new byte[]{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
            SdkBytes encryptedData = encryptData(kmsClient, keyId, data);
            System.out.println("After encryption: ");
            printHexString(encryptedData.asByteArray());
            byte[] decryptedData = decryptData(kmsClient, encryptedData, keyId);
            System.out.println("After decryption: ");
            printHexString(decryptedData);
            System.out.println("is decryption correct? " + Arrays.equals(data, decryptedData));
            System.out.println("Done");
        }
    }

    public static SdkBytes encryptData(KmsClient kmsClient, String keyId, byte[] data) {
        try {
            SdkBytes myBytes = SdkBytes.fromByteArray(data);
            EncryptRequest encryptRequest = EncryptRequest.builder()
                    .keyId(keyId)
                    .plaintext(myBytes)
                    .encryptionContext(
                            Map.of("keyId", keyId,
                                    "region", Region.AP_NORTHEAST_1.id()))
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

    public static byte[] decryptData(KmsClient kmsClient, SdkBytes encryptedData, String keyId) {
        try {
            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(encryptedData)
                    .keyId(keyId)
                    .encryptionContext(
                            Map.of("keyId", keyId,
                                    "region", Region.AP_NORTHEAST_1.id()))
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
