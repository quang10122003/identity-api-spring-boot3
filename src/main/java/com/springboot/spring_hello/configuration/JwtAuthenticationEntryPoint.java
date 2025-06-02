package com.springboot.spring_hello.configuration;

import java.io.IOException;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springboot.spring_hello.DTO.response.ApiResponse;
import com.springboot.spring_hello.exception.ErrorCode;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


// **
//  * Lớp JwtAuthenticationEntryPoint chịu trách nhiệm xử lý các trường hợp người dùng 
//  * truy cập vào tài nguyên cần xác thực nhưng chưa được xác thực (unauthenticated).
//  * 
//  * Khi có lỗi AuthenticationException xảy ra (ví dụ: thiếu hoặc token không hợp lệ),
//  * lớp này sẽ can thiệp và trả về cho client một phản hồi JSON theo định dạng chuẩn,
//  * bao gồm:
//  * - HTTP Status code từ ErrorCode.UN_AUTHENTICATED
//  * - Nội dung JSON với mã lỗi và thông điệp lỗi
//  * 
//  * Mục đích là giúp client hiểu rõ lý do từ chối truy cập thay vì nhận lỗi mặc định.
//  */

// vì exception này xử lý ở filter của scurity của springboot chưa vào đến src code nên phải viết 1 class triển khai AuthenticationEntryPoint để custom sau đó tùy chỉnh ở SecurityFilterChain trong scurityConfigConfig
public class JwtAuthenticationEntryPoint  implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
                ErrorCode errorCode = ErrorCode.UN_AUTHENTICATED;
                // status code 
                response.setStatus(errorCode.getStatusCode().value());
                // kiểu body trả về 
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                // body trả về 
                ApiResponse<?> apiResponse = ApiResponse.builder()
                .code(errorCode.getCode())
                .message(errorCode.getMessage())
                .build();

                // viết nội dung trả về 
                ObjectMapper objectMapper = new ObjectMapper();

                response.getWriter().write(objectMapper.writeValueAsString(apiResponse));

                // commit repone về 
                response.flushBuffer(); 
    }
    
}
