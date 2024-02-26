package com.lgypro.kms;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.VerifyRequest;
import software.amazon.awssdk.services.kms.model.VerifyResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SignAndVerify {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String message = """
                我小心翼翼的接近
                怕你在梦中惊醒
                我只是想轻轻地吻吻你
                你别担心
                我知道想要和你在一起并不容易
                我们来自不同的天和地
                你总是感觉
                和我一起 是漫无边际阴冷的恐惧
                我真的好爱你
                我愿意改变自己
                我愿意为你流浪在戈壁
                只求你不要拒绝 不要离别
                不要给我风雪
                我真的好爱你
                我愿意改变自己
                我愿意为你背负一身羊皮
                只求你让我靠近 让我爱你
                相偎相依
                我确定我就是那一只披着羊皮的狼
                而你是我的猎物
                是我嘴里的羔羊
                我抛却同伴独自流浪
                就是不愿别人把你分享
                我确定这一辈子都会在你身旁
                带着火热的心随你到任何地方
                你让我痴 让我狂
                爱你的嚎叫还在山谷回荡
                我确定你就是我心中如花的羔羊
                你是我的天使是我的梦想
                我搂你在怀里 装进我的身体
                让你我的血液交融在一起
                你确定看到我为你披上那温柔的羊皮
                是一个男人无法表露脆弱的感情
                我有多爱你 就有多少柔情
                我相信这柔情定能感动天地
                """;
        Region region = Region.AP_NORTHEAST_1;
        String keyId = "arn:aws:kms:ap-northeast-1:345164961032:key/6c807240-f7c2-44e4-becc-c41104442497";
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8));
        String signingAlgorithm = "RSASSA_PSS_SHA_256";

        try (KmsClient kmsClient = KmsClient.builder().region(region).build()) {
            byte[] signature = sign(kmsClient, keyId, signingAlgorithm, digest, "DIGEST");
            boolean result = verify(kmsClient, keyId, signingAlgorithm, message.getBytes(StandardCharsets.UTF_8), "RAW", signature);
            System.out.println("is signature ok? " + result);
        }
    }

    public static byte[] sign(KmsClient client, String keyId, String signingAlgorithm, byte[] message, String messageType) {
        SignRequest request = SignRequest.builder()
                .keyId(keyId)
                .signingAlgorithm(signingAlgorithm)
                .message(SdkBytes.fromByteArray(message))
                .messageType(messageType)
                .build();
        SignResponse response = client.sign(request);
        return response.signature().asByteArray();
    }

    public static boolean verify(KmsClient client, String keyId, String signingAlgorithm, byte[] message, String messageType, byte[] signature) {
        VerifyRequest request = VerifyRequest.builder()
                .keyId(keyId)
                .signingAlgorithm(signingAlgorithm)
                .message(SdkBytes.fromByteArray(message))
                .messageType(messageType)
                .signature(SdkBytes.fromByteArray(signature)).build();
        VerifyResponse response = client.verify(request);
        return response.signatureValid();
    }
}
