package com.lgypro.kms;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

public class ReEncrypt {
    public static void main(String[] args) {
        /*
        先用对称加密，再用非对称加密，最后解密
         */
        Region region = Region.AP_NORTHEAST_1;
        String sourceKeyId = "arn:aws:kms:ap-northeast-1:345164961032:key/7d0b4bb5-3ed7-45c6-bb1f-2dfd53a4cd47";
        String destinationKeyId = "arn:aws:kms:ap-northeast-1:345164961032:key/906d0359-e2a7-4cb5-971f-f6a7354721e3";
        String destinationEncryptionAlgorithm = "RSAES_OAEP_SHA_256";
        Map<String, String> sourceEncryptionContext = Map.of(
                "keyId", sourceKeyId,
                "region", Region.AP_NORTHEAST_1.id());
        byte[] data = """
                孩儿立志出乡关，
                学不成名誓不还。
                埋骨何须桑梓地，
                人生无处不青山。
                """.getBytes(StandardCharsets.UTF_8);
        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            byte[] encryptedData = encrypt(kmsClient, sourceKeyId, data, sourceEncryptionContext);
            byte[] reEncryptedData = reEncrypt(kmsClient,
                    sourceKeyId,
                    sourceEncryptionContext,
                    destinationKeyId,
                    destinationEncryptionAlgorithm,
                    encryptedData);
            byte[] newData = decrypt(kmsClient, destinationKeyId, destinationEncryptionAlgorithm, reEncryptedData);
            System.out.println("is recovery success? " + Arrays.equals(data, newData));
            System.out.println(new String(newData, StandardCharsets.UTF_8));
        }
    }

    /*
    对称加密
     */
    public static byte[] encrypt(KmsClient kmsClient, String keyId, byte[] data, Map<String, String> encryptionContext) {
        try {
            EncryptRequest encryptRequest = EncryptRequest.builder()
                    .keyId(keyId)
                    .plaintext(SdkBytes.fromByteArray(data))
                    .encryptionContext(encryptionContext)
                    .build();
            EncryptResponse response = kmsClient.encrypt(encryptRequest);
            return response.ciphertextBlob().asByteArray();
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
        return null;
    }

    public static byte[] reEncrypt(KmsClient kmsClient,
                                   String sourceKeyId,
                                   Map<String, String> sourceEncryptionContext,
                                   String destinationKeyId,
                                   String destinationEncryptionAlgorithm,
                                   byte[] ciphertext) {
        ReEncryptRequest request = ReEncryptRequest.builder()
                .sourceKeyId(sourceKeyId)
                .sourceEncryptionContext(sourceEncryptionContext)
                .destinationKeyId(destinationKeyId)
                .destinationEncryptionAlgorithm(destinationEncryptionAlgorithm)
                .ciphertextBlob(SdkBytes.fromByteArray(ciphertext)).build();
        ReEncryptResponse response = kmsClient.reEncrypt(request);
        return response.ciphertextBlob().asByteArray();
    }

    /*
    非对称解密
     */
    public static byte[] decrypt(KmsClient kmsClient, String keyId, String encryptionAlgorithm, byte[] encryptedData) {
        try {
            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedData))
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
}
