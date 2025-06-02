package com.springboot.spring_hello.configuration;

import com.nimbusds.jose.JOSEException;
import com.springboot.spring_hello.DTO.Request.IntrospectRequest;
import com.springboot.spring_hello.DTO.response.IntrospectResponse;
import com.springboot.spring_hello.exception.AppExcetion;
import com.springboot.spring_hello.exception.ErrorCode;
import com.springboot.spring_hello.service.interfaces.AuthenticationService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
// class  cung cấp cấu hình verity token cho security
@Component
public class CustomJwtDecoder implements JwtDecoder {

    private final NimbusJwtDecoder nimbusJwtDecoder;

    public CustomJwtDecoder(@Value("${jwt.signerKey}") String signerKey) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(), "HS512");
        this.nimbusJwtDecoder = NimbusJwtDecoder
                .withSecretKey(secretKeySpec)
                .macAlgorithm(MacAlgorithm.HS512)
                .build();
    }

    @Autowired
    private AuthenticationService authenticationService;

    @Override
    public Jwt decode(String token) throws JwtException {
       
             // check xem token còn hơp lệ
            try {
                IntrospectResponse response =  authenticationService.introspect(IntrospectRequest.builder()
                        .token(token)
                        .build());
                        // nếu token hết hạn or sai or đã logout 
                        if(!(response.isValid())){
                            throw new AppExcetion(ErrorCode.UN_AUTHENTICATED);
                        }
            } catch (JOSEException | ParseException e) {
                throw new JwtException(e.getMessage());
            }
        
        // token hợp lệ trả về JWt;
        return nimbusJwtDecoder.decode(token);
    }
}