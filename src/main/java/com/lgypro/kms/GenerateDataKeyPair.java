package com.lgypro.kms;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class GenerateDataKeyPair {
    public static void main(String[] args) {
        Region region = Region.AP_NORTHEAST_1;
        String keyId = "arn:aws:kms:ap-northeast-1:345164961032:key/7d0b4bb5-3ed7-45c6-bb1f-2dfd53a4cd47";
        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            String keySpec = "RSA_4096";
            Map<String, String> encryptionContext = Map.of("keyId", keyId,
                    "region", Region.AP_NORTHEAST_1.id());
            List<byte[]> keyList = generateDataKeyPair(kmsClient, keyId, keySpec, encryptionContext);
            System.out.println("public key is: ");
            printHexString(keyList.get(0));
            System.out.println("private key plaintext is: ");
            printHexString(keyList.get(1));
            System.out.println("private key ciphertext is: ");
            printHexString(keyList.get(2));
            byte[] decryptedPrivateKey = decryptData(kmsClient, keyId, keyList.get(2), encryptionContext);
            System.out.println("decrypted private key is: ");
            printHexString(decryptedPrivateKey);
            System.out.println("is decryption correct? " + Arrays.equals(keyList.get(1), decryptedPrivateKey));
        }
    }

    public static List<byte[]> generateDataKeyPair(KmsClient kmsClient, String keyId, String keyPairSpec, Map<String, String> encryptionContext) {
        GenerateDataKeyPairRequest request = GenerateDataKeyPairRequest.builder()
                .keyId(keyId)
                .keyPairSpec(keyPairSpec)
                .encryptionContext(encryptionContext)
                .build();
        GenerateDataKeyPairResponse response = kmsClient.generateDataKeyPair(request);
        byte[] publicKey = response.publicKey().asByteArray();
        byte[] privateKeyPlaintext = response.privateKeyPlaintext().asByteArray();
        byte[] privateKeyCiphertext = response.privateKeyCiphertextBlob().asByteArray();
        return List.of(publicKey, privateKeyPlaintext, privateKeyCiphertext);
    }

    public static void printHexString(byte[] data) {
        int length = data.length;
        for (int i = 0; i < length; i++) {
            if ((i + 1) % 32 == 0) {
                System.out.printf("%02x%n", data[i]);
            } else {
                System.out.printf("%02x ", data[i]);
            }
        }
        System.out.println();
    }

    public static byte[] decryptData(KmsClient kmsClient, String keyId, byte[] data, Map<String, String> encryptionContext) {
        try {
            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(data))
                    .keyId(keyId)
                    .encryptionContext(encryptionContext)
                    .build();
            DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
            return decryptResponse.plaintext().asByteArray();
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return null;
        }
    }
}
