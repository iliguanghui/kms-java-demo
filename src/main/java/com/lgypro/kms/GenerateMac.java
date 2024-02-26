package com.lgypro.kms;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GenerateMacRequest;
import software.amazon.awssdk.services.kms.model.GenerateMacResponse;
import software.amazon.awssdk.services.kms.model.VerifyMacRequest;
import software.amazon.awssdk.services.kms.model.VerifyMacResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class GenerateMac {
    public static void main(String[] args) {
        Region region = Region.AP_NORTHEAST_1;
        String keyId = "8db9314b-e439-4e7e-b7a7-4b55801baeb3";
        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            byte[] message = """
                    风雨送春归，
                    飞雪迎春到。
                    已是悬崖百丈冰，
                    犹有花枝俏。
                    俏也不争春，
                    只把春来报。
                    待到山花烂漫时，
                    她在丛中笑。""".getBytes(StandardCharsets.UTF_8);
            String macAlgorithm = "HMAC_SHA_256";
            byte[] mac = generateMac(kmsClient, keyId, macAlgorithm, message);
            System.out.println("message is " + Base64.getEncoder().encodeToString(message));
            System.out.println("mac is " + Base64.getEncoder().encodeToString(mac));
            System.out.println("--------------------------");
            boolean isValid = verifyMac(kmsClient, keyId, macAlgorithm, message, mac);
            System.out.println("is mac valid? " + isValid);
        }
    }

    public static byte[] generateMac(KmsClient kmsclient, String keyId, String macAlgorithm, byte[] message) {
        GenerateMacRequest request = GenerateMacRequest.builder()
                .keyId(keyId)
                .macAlgorithm(macAlgorithm)
                .message(SdkBytes.fromByteArray(message)).build();
        GenerateMacResponse response = kmsclient.generateMac(request);
        return response.mac().asByteArray();
    }

    public static boolean verifyMac(KmsClient kmsclient, String keyId, String macAlgorithm, byte[] message, byte[] mac) {
        VerifyMacRequest request = VerifyMacRequest.builder()
                .keyId(keyId)
                .macAlgorithm(macAlgorithm)
                .message(SdkBytes.fromByteArray(message))
                .mac(SdkBytes.fromByteArray(mac)).build();
        VerifyMacResponse response = kmsclient.verifyMac(request);
        return response.macValid();
    }
}
