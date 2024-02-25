package com.lgypro.kms;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.KmsException;

public class DescribeKey {
    public static void main(String[] args) {
        Region region = Region.AP_NORTHEAST_1;
        String keyId = "2f88b031-5b13-4ab6-aca1-0c8769bca35c";
        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            describeSpecifcKey(kmsClient, keyId);
        }
    }

    public static void describeSpecifcKey(KmsClient kmsClient, String keyId) {
        try {
            DescribeKeyRequest keyRequest = DescribeKeyRequest.builder()
                    .keyId(keyId)
                    .build();
            DescribeKeyResponse response = kmsClient.describeKey(keyRequest);
            System.out.println("The key description is " + response.keyMetadata().description());
            System.out.println("The key ARN is " + response.keyMetadata().arn());
            System.out.println("The key manager is " + response.keyMetadata().keyManager());
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }
}
