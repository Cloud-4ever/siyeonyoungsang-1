package com.shopeasy.api.dto.response;

public class UploadResponse {

    private String fileUrl;
    private String uploadUrl;

    public UploadResponse() {
    }

    public UploadResponse(String fileUrl) {
        this.fileUrl = fileUrl;
    }

    public UploadResponse(String uploadUrl, String fileUrl) {
        this.uploadUrl = uploadUrl;
        this.fileUrl = fileUrl;
    }

    public String getFileUrl() {
        return fileUrl;
    }

    public void setFileUrl(String fileUrl) {
        this.fileUrl = fileUrl;
    }

    public String getUploadUrl() {
        return uploadUrl;
    }

    public void setUploadUrl(String uploadUrl) {
        this.uploadUrl = uploadUrl;
    }
}
