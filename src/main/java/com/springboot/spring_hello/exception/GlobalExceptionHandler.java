package com.springboot.spring_hello.exception;

import java.nio.file.AccessDeniedException;
import java.util.Map;
import java.util.Objects;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.springboot.spring_hello.DTO.response.ApiResponse;
import com.springboot.spring_hello.validator.NgaySinhContraint;

import jakarta.validation.ConstraintViolation;
import lombok.experimental.var;

@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(value = Exception.class)
    private ResponseEntity<ApiResponse> handlingException(RuntimeException e){
        ApiResponse apiResponse = new ApiResponse<>();
        apiResponse.setCode(ErrorCode.OTHER_EXCEPTION.getCode());
        apiResponse.setMessage(ErrorCode.OTHER_EXCEPTION.getMessage());

        return ResponseEntity.status(ErrorCode.OTHER_EXCEPTION.getStatusCode()).body(apiResponse);
    }


// bắt AccessDeniedException ko có quyền truy cập Authorization 
    @ExceptionHandler(value = org.springframework.security.access.AccessDeniedException.class)
    private ResponseEntity<ApiResponse> handlingAccessDeniedException(org.springframework.security.access.AccessDeniedException exception){
        ErrorCode errorCode = ErrorCode.UN_Authorization;

        return ResponseEntity
        .status(errorCode.getStatusCode())
        .body(
            ApiResponse.builder()
            .code(errorCode.getCode())
            .message(errorCode.getMessage())
            .build()
        );
    }


    @ExceptionHandler(value = AppExcetion.class)
    private ResponseEntity<ApiResponse> handlingAppException(AppExcetion e){
        ApiResponse apiResponse = new ApiResponse<>();
        ErrorCode errorCode = e.getErrorCode();
        apiResponse.setCode(errorCode.getCode());
        apiResponse.setMessage(errorCode.getMessage());
        return ResponseEntity
        .status(errorCode.getStatusCode())
        .body(apiResponse);
    }


    
    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    private ResponseEntity<ApiResponse> handlingNotValidException
    (MethodArgumentNotValidException exception){
        Map<String,Object> attributes = null;
        String enumkey = exception.getFieldError().getDefaultMessage();
        System.out.println(exception.getFieldError().getDefaultMessage());
        ErrorCode errorCode = ErrorCode.NO_KEY;
         // lấy thông tin của anotation 
            var contrainViolation = exception.getBindingResult().getAllErrors().getFirst().unwrap(ConstraintViolation.class);
            attributes = contrainViolation.getConstraintDescriptor().getAttributes();
            System.out.println(attributes.toString());
        try {
            errorCode = ErrorCode.valueOf(enumkey);
           
        } catch (IllegalArgumentException ex) {
            System.out.println("ko tim thay ma code ");
        }
        ApiResponse apiResponse = new ApiResponse<>();
        apiResponse.setCode(errorCode.getCode());
        apiResponse.setMessage(Objects.nonNull(attributes)? mapAttributes(errorCode.getMessage(), attributes)
        :errorCode.getMessage());
        return ResponseEntity.badRequest().body(apiResponse);
    }


    // hàm truyền min của anotation vào mess của ercode 
    private String mapAttributes(String message , Map<String, Object> attributes){
        String minValue = String.valueOf(attributes.get("min")) ;
        return message.replace("{min}", minValue);
    }
}