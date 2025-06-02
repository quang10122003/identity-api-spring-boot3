package com.springboot.spring_hello.controller;

import java.text.ParseException;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JOSEException;
import com.springboot.spring_hello.DTO.Request.AuthenticationRequest;
import com.springboot.spring_hello.DTO.Request.IntrospectRequest;
import com.springboot.spring_hello.DTO.Request.InvalidatedTokenRequest;
import com.springboot.spring_hello.DTO.Request.RefreshTokenRequest;
import com.springboot.spring_hello.DTO.response.ApiResponse;
import com.springboot.spring_hello.DTO.response.AuthenticationReponse;
import com.springboot.spring_hello.DTO.response.IntrospectResponse;
import com.springboot.spring_hello.DTO.response.RefreshTokenResponse;
import com.springboot.spring_hello.service.interfaces.AuthenticationService;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.var;
import lombok.experimental.FieldDefaults;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE,makeFinal = true)
public class AuthenticationController {
    AuthenticationService authenticationService;

    @PostMapping("/login")
    ApiResponse<AuthenticationReponse> authenticate(@RequestBody AuthenticationRequest authenticationRequest){
        AuthenticationReponse result = authenticationService.authentication(authenticationRequest);
        return ApiResponse.<AuthenticationReponse>builder()
               .code(200)
               .result(result)
               .build();
    }
// check token 
    @PostMapping("/Introspect")
    ApiResponse<IntrospectResponse> authenticateIntrospect(@RequestBody IntrospectRequest request) throws Exception, ParseException{
        IntrospectResponse result = authenticationService.introspect(request);
        return ApiResponse.<IntrospectResponse>builder()
        .code(200)
        .result(result)
        .build();
    }

    @PostMapping("/logout")
    ApiResponse<Void> logout(@RequestBody InvalidatedTokenRequest request) throws ParseException, JOSEException{
        authenticationService.logout(request);
        return ApiResponse.<Void>builder()
        .code(200) 
        .message("đăng xuất thành công")
        .build();
    }

    @PostMapping("/RefreshToken")
    ApiResponse<RefreshTokenResponse> refreshToken(@RequestBody RefreshTokenRequest request) throws ParseException, JOSEException{
        RefreshTokenResponse result = authenticationService.refreshToken(request);
        return ApiResponse.<RefreshTokenResponse>builder()
        .code(200)
        .result(result)
        .build();
    }
}
