package com.shopeasy.api.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@Service
public class StorageService {

    @Value("${app.storage.type}")
    private String storageType;

    @Value("${app.storage.s3.bucket:}")
    private String s3Bucket;

    @Value("${app.storage.s3.region:ap-northeast-2}")
    private String s3Region;

    @Autowired
    @Lazy
    private S3Client s3Client;

    @Autowired
    @Lazy
    private S3Presigner s3Presigner;

    public String getStorageType() {
        return storageType;
    }

    public String uploadFile(MultipartFile file) throws IOException {
        String originalFilename = file.getOriginalFilename();
        String extension = "";
        if (originalFilename != null && originalFilename.contains(".")) {
            extension = originalFilename.substring(originalFilename.lastIndexOf("."));
        }
        String fileName = UUID.randomUUID().toString() + extension;

        if ("s3".equals(storageType)) {
            return uploadToS3(fileName, file.getBytes(), file.getContentType());
        } else {
            return uploadToLocal(fileName, file);
        }
    }

    private String uploadToLocal(String fileName, MultipartFile file) throws IOException {
        Path uploadDir = Paths.get("./uploads");
        if (!Files.exists(uploadDir)) {
            Files.createDirectories(uploadDir);
        }
        Path filePath = uploadDir.resolve(fileName);
        file.transferTo(filePath.toFile());
        return "/uploads/" + fileName;
    }

    private String uploadToS3(String fileName, byte[] data, String contentType) {
        String key = "uploads/" + fileName;

        PutObjectRequest putRequest = PutObjectRequest.builder()
                .bucket(s3Bucket)
                .key(key)
                .contentType(contentType)
                .build();

        s3Client.putObject(putRequest, RequestBody.fromBytes(data));

        return String.format("https://%s.s3.%s.amazonaws.com/%s", s3Bucket, s3Region, key);
    }

    public Map<String, String> generatePresignedUrl(String fileName, String fileType) {
        String extension = "";
        if (fileName != null && fileName.contains(".")) {
            extension = fileName.substring(fileName.lastIndexOf("."));
        }
        String key = "uploads/" + UUID.randomUUID().toString() + extension;

        if ("s3".equals(storageType)) {
            PutObjectRequest putRequest = PutObjectRequest.builder()
                    .bucket(s3Bucket)
                    .key(key)
                    .contentType(fileType)
                    .build();

            PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
                    .signatureDuration(Duration.ofMinutes(15))
                    .putObjectRequest(putRequest)
                    .build();

            String uploadUrl = s3Presigner.presignPutObject(presignRequest).url().toString();
            String fileUrl = String.format("https://%s.s3.%s.amazonaws.com/%s", s3Bucket, s3Region, key);

            return Map.of("uploadUrl", uploadUrl, "fileUrl", fileUrl);
        } else {
            String fileUrl = "/uploads/" + key.replace("uploads/", "");
            return Map.of("uploadUrl", "/api/upload", "fileUrl", fileUrl);
        }
    }
}
