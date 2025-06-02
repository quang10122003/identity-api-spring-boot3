package com.springboot.spring_hello.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Getter
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public enum ErrorCode {
    USER_EXISTED(1001, "User đã tồn tại", HttpStatus.BAD_REQUEST),
    USER_minBOB(1001, "bạn chưa đủ {min} tuổi ", HttpStatus.BAD_REQUEST),
    OTHER_EXCEPTION(999, "other exceptions", HttpStatus.INTERNAL_SERVER_ERROR),
    USER_NAME_MIN(8888, "user name phải có ít nhất 3 ký tự", HttpStatus.BAD_REQUEST),
    PASSWORD_MIN(8888, "PASS WORD phải có ít nhất 3 ký tự", HttpStatus.BAD_REQUEST),
    NO_KEY(8881, "no key", HttpStatus.BAD_REQUEST),
    NO_USER(8881, "ko tim thay user", HttpStatus.BAD_REQUEST),
    USER_NO_EXISTED(1001, "user ko ton tai", HttpStatus.NOT_FOUND),
    UN_AUTHENTICATED(1007, "bạn ko có quyền truy cập ", HttpStatus.UNAUTHORIZED),
    NO_PASSWORD(1009, "pass ko dc trong ", HttpStatus.BAD_REQUEST),
    UN_Authorization(1010,"ko có quyền truy cập endpoint",HttpStatus.FORBIDDEN) ;


    int code;
    String message;
    HttpStatusCode statusCode;

}
