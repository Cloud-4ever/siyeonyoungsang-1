package com.shopeasy.api.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

import java.util.Map;

@Service
public class QueueService {

    @Value("${app.queue.type}")
    private String queueType;

    @Value("${app.queue.sqs.queue-url:}")
    private String sqsQueueUrl;

    @Value("${app.queue.sns.topic-arn:}")
    private String snsTopicArn;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    @Lazy
    private SqsClient sqsClient;

    @Autowired
    @Lazy
    private SnsClient snsClient;

    public String getQueueType() {
        return queueType;
    }

    public void sendOrderMessage(Map<String, Object> orderData) {
        try {
            String message = objectMapper.writeValueAsString(orderData);

            if ("sqs".equals(queueType) || "aws".equals(queueType)) {
                sendToSqs(message);
            } else if ("sns".equals(queueType)) {
                sendToSns(message);
            } else {
                System.out.println("[Queue-Sync] Order message: " + message);
            }
        } catch (Exception e) {
            System.err.println("Queue send error: " + e.getMessage());
        }
    }

    private void sendToSqs(String message) {
        if (sqsQueueUrl == null || sqsQueueUrl.isEmpty()) {
            System.out.println("[Queue-SQS] No queue URL configured, logging: " + message);
            return;
        }

        SendMessageRequest request = SendMessageRequest.builder()
                .queueUrl(sqsQueueUrl)
                .messageBody(message)
                .build();

        sqsClient.sendMessage(request);
        System.out.println("[Queue-SQS] Message sent to: " + sqsQueueUrl);
    }

    private void sendToSns(String message) {
        if (snsTopicArn == null || snsTopicArn.isEmpty()) {
            System.out.println("[Queue-SNS] No topic ARN configured, logging: " + message);
            return;
        }

        PublishRequest request = PublishRequest.builder()
                .topicArn(snsTopicArn)
                .message(message)
                .subject("New Order")
                .build();

        snsClient.publish(request);
        System.out.println("[Queue-SNS] Message published to: " + snsTopicArn);
    }
}
