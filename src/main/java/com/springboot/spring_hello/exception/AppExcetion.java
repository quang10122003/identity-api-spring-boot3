package com.springboot.spring_hello.exception;

public class AppExcetion extends RuntimeException {
    private ErrorCode errorCode;

    public AppExcetion(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return this.errorCode;
    }

    public void setErrorCode(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

}
