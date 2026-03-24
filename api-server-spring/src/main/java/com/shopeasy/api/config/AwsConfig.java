package com.shopeasy.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sqs.SqsClient;

@Configuration
public class AwsConfig {

    @Value("${app.storage.s3.region:ap-northeast-2}")
    private String s3Region;

    @Value("${app.review.dynamodb.region:ap-northeast-2}")
    private String dynamoDbRegion;

    @Value("${app.aws.region:ap-northeast-2}")
    private String defaultRegion;

    @Bean
    @Lazy
    public S3Client s3Client() {
        return S3Client.builder()
                .region(Region.of(s3Region))
                .build();
    }

    @Bean
    @Lazy
    public S3Presigner s3Presigner() {
        return S3Presigner.builder()
                .region(Region.of(s3Region))
                .build();
    }

    @Bean
    @Lazy
    public DynamoDbClient dynamoDbClient() {
        return DynamoDbClient.builder()
                .region(Region.of(dynamoDbRegion))
                .build();
    }

    @Bean
    @Lazy
    public SqsClient sqsClient() {
        return SqsClient.builder()
                .region(Region.of(defaultRegion))
                .build();
    }

    @Bean
    @Lazy
    public SnsClient snsClient() {
        return SnsClient.builder()
                .region(Region.of(defaultRegion))
                .build();
    }
}
