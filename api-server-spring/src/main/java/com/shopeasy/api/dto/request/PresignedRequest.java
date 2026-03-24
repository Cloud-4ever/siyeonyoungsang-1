package com.shopeasy.api.dto.request;

public class PresignedRequest {

    private String fileName;
    private String fileType;

    public PresignedRequest() {
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getFileType() {
        return fileType;
    }

    public void setFileType(String fileType) {
        this.fileType = fileType;
    }
}
