package com.lgypro.kms;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KeyListEntry;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.ListKeysResponse;

import java.util.List;

public class ListKeys {
    public static void main(String[] args) {
        Region region = Region.AP_NORTHEAST_1;
        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            listAllKeys(kmsClient);
        }
    }

    public static void listAllKeys(KmsClient kmsClient) {
        try {
            ListKeysResponse response = kmsClient.listKeys();
            List<KeyListEntry> keyList = response.keys();
            for (KeyListEntry key : keyList) {
                System.out.println("The key ARN is: " + key.keyArn());
                System.out.println("The key Id is: " + key.keyId());
            }
        } catch (KmsException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}


