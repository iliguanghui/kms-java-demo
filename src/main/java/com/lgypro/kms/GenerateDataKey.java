package com.lgypro.kms;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class GenerateDataKey {
    public static void main(String[] args) {

        Region region = Region.AP_NORTHEAST_1;
        String keyId = "arn:aws:kms:ap-northeast-1:345164961032:key/7d0b4bb5-3ed7-45c6-bb1f-2dfd53a4cd47";
        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            byte[] data = "hello world\n".getBytes(StandardCharsets.US_ASCII);
            String keySpec = "AES_256";
            Map<String, String> encryptionContext = Map.of("keyId", keyId,
                    "region", Region.AP_NORTHEAST_1.id());
            // 创建一个数据密钥
            List<byte[]> keyList = generateDataKey(kmsClient, keyId, keySpec, encryptionContext);
            System.out.println("Encrypted data key is: ");
            printHexString(keyList.get(1));
            String cipher_algorithm = "AES/CBC/PKCS5Padding";
            String algorithm = "AES";
            byte[] iv = "0123456789012345".getBytes(StandardCharsets.US_ASCII);
            // 使用明文数据密钥加密数据AES-256-CBC
            byte[] encryptedData = encode(algorithm, cipher_algorithm, keyList.get(0), iv, data);
            System.out.println("After data key encryption: ");
            printHexString(encryptedData);
            System.out.println("base64 encrypted: " + Base64.getEncoder().encodeToString(encryptedData));
            // 调用KMS服务解密出明文数据密钥
            byte[] plaintextDataKey = decryptDataKey(kmsClient, SdkBytes.fromByteArray(keyList.get(1)), keyId, encryptionContext);
            // 使用数据密钥解密出明文数据
            byte[] originalData = decode(algorithm, cipher_algorithm, plaintextDataKey, iv, encryptedData);
            System.out.println("After decryption: ");
            printHexString(originalData);
            System.out.println("is decryption correct? " + Arrays.equals(data, originalData));
            System.out.println("Done");
        }
    }

    public static List<byte[]> generateDataKey(KmsClient kmsClient, String keyId, String keySpec, Map<String, String> encryptionContext) {
        GenerateDataKeyRequest request = GenerateDataKeyRequest.builder()
                .keyId(keyId)
                .keySpec(keySpec)
                .encryptionContext(encryptionContext)
                .build();
        GenerateDataKeyResponse response = kmsClient.generateDataKey(request);
        byte[] plaintextDataKey = response.plaintext().asByteArray();
        byte[] encryptedDataKey = response.ciphertextBlob().asByteArray();
        return List.of(plaintextDataKey, encryptedDataKey);
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

    public static byte[] encode(String algorithm, String cipherAlgorithm, byte[] key, byte[] iv, byte[] data) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedData = cipher.doFinal(data);
            return encryptedData;
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }

    public static byte[] decode(String algorithm, String cipherAlgorithm, byte[] key, byte[] iv, byte[] data) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decryptedData = cipher.doFinal(data);
            return decryptedData;
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }


    public static byte[] decryptDataKey(KmsClient kmsClient, SdkBytes encryptedData, String keyId, Map<String, String> encryptionContext) {
        try {
            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(encryptedData)
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
