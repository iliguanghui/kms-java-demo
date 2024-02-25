package com.lgypro.kms;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.AliasListEntry;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.ListAliasesResponse;

import java.util.List;

public class ListAllAliases {
    public static void main(String[] args) {
        Region region = Region.AP_NORTHEAST_1;
        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            listAllAliases(kmsClient);
        }
    }

    public static void listAllAliases(KmsClient kmsClient) {
        try {
            ListAliasesResponse response = kmsClient.listAliases();
            List<AliasListEntry> aliases = response.aliases();
            for (AliasListEntry alias : aliases) {
                System.out.println("The alias name is: " + alias.aliasName());
            }
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }
}
