package com.springboot.spring_hello.service.interfaces;

import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.springboot.spring_hello.DTO.Request.AuthenticationRequest;
import com.springboot.spring_hello.DTO.Request.IntrospectRequest;
import com.springboot.spring_hello.DTO.Request.InvalidatedTokenRequest;
import com.springboot.spring_hello.DTO.Request.RefreshTokenRequest;
import com.springboot.spring_hello.DTO.response.AuthenticationReponse;
import com.springboot.spring_hello.DTO.response.IntrospectResponse;
import com.springboot.spring_hello.DTO.response.RefreshTokenResponse;
import com.springboot.spring_hello.entitys.User;

public interface AuthenticationService {
    AuthenticationReponse authentication(AuthenticationRequest authenticationRequest);
    String genToken(User user);
    IntrospectResponse introspect(IntrospectRequest introspectRequest) throws JOSEException, ParseException;
    String buildScope(User user);
    void logout(InvalidatedTokenRequest invalidatedTokenRequest)throws ParseException, JOSEException;
    SignedJWT verifierToken(String token) throws ParseException, JOSEException;
    RefreshTokenResponse refreshToken(RefreshTokenRequest request)throws ParseException, JOSEException ;
}
