package com.springboot.spring_hello.service.implement;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.StringJoiner;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.springboot.spring_hello.DTO.Request.AuthenticationRequest;
import com.springboot.spring_hello.DTO.Request.IntrospectRequest;
import com.springboot.spring_hello.DTO.Request.InvalidatedTokenRequest;
import com.springboot.spring_hello.DTO.Request.RefreshTokenRequest;
import com.springboot.spring_hello.DTO.response.AuthenticationReponse;
import com.springboot.spring_hello.DTO.response.IntrospectResponse;
import com.springboot.spring_hello.DTO.response.RefreshTokenResponse;
import com.springboot.spring_hello.entitys.InvalidatedToken;
import com.springboot.spring_hello.entitys.User;
import com.springboot.spring_hello.exception.AppExcetion;
import com.springboot.spring_hello.exception.ErrorCode;
import com.springboot.spring_hello.repository.InvalidatedTokenRepository;
import com.springboot.spring_hello.repository.UserRepository;
import com.springboot.spring_hello.service.interfaces.AuthenticationService;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationServiceImpl implements AuthenticationService {

    UserRepository userRepository;
    InvalidatedTokenRepository invalidatedTokenRepository;
    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
    @NonFinal // ko inject vào hàm khởi tạo
    @Value("${jwt.signerKey}")
    protected String SIGNER_KEY;

    // đăng nhập nếu đúng trả về token nếu sai trả lỗi
    @Override
    public AuthenticationReponse authentication(AuthenticationRequest authenticationRequest) {
        User user = userRepository.findByUsername(authenticationRequest.getUsername()).orElseThrow(() -> {
            return new AppExcetion(ErrorCode.USER_NO_EXISTED);
        });
        boolean authenticated = passwordEncoder.matches(authenticationRequest.getPassword(), user.getPassword());
        if (!authenticated) {
            throw new AppExcetion(ErrorCode.UN_AUTHENTICATED);
        }
        String token = genToken(user);
        return AuthenticationReponse.builder()
                .token(token)
                .authenticated(true)
                .build();

    }

    // hàm tạo token
    @Override
    public String genToken(User user) {
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS512); // THuật toán mã hóa token
        // thân của token payload
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                // user name để lấy trong SecurityContextHolder
                .subject(user.getUsername())
                .issuer("quangcuon.com")
                // thời gian tạo
                .issueTime(new Date())
                // thời gian hết hạn
                .expirationTime(new Date(Instant.now().plus(1, ChronoUnit.HOURS).toEpochMilli()))
                // tạo scope role để phân quyền
                .claim("scope", this.buildScope(user))
                // taọ id cho token để lưu trữ vô hiệu hóa token
                .jwtID(UUID.randomUUID().toString())
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());
        JWSObject jwsObject = new JWSObject(jwsHeader, payload);
        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));
            return jwsObject.serialize();
        } catch (Exception e) {
            System.err.println("k tao dc token");
            throw new RuntimeException(e);
        }

    }

    // check token có hợp lệ hay k
    @Override
    public IntrospectResponse introspect(IntrospectRequest introspectRequest) throws JOSEException, ParseException {
        String token = introspectRequest.getToken();
        boolean isvald = true;
        String mess = "token hợp lệ";
        try {
            this.verifierToken(token);
        } catch (AppExcetion e) {
            isvald = false;
            mess = "token k hợp lệ";
        }

        return IntrospectResponse.builder()
                .valid(isvald)
                .massge(mess)
                .build();

    }

    public SignedJWT verifierToken(String token) throws ParseException, JOSEException {
        // Tạo đối tượng JWSVerifier dùng để xác thực chữ ký JWT dựa trên khóa bí mật
        // (dưới dạng mảng byte)
        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());
        // Phân tích chuỗi JWT token thành đối tượng SignedJWT để truy cập các claims và
        // xác thực chữ ký
        SignedJWT signedJWT = SignedJWT.parse(token);
        // lấy time hết hạn token
        Date expitytimeToken = signedJWT.getJWTClaimsSet().getExpirationTime();
        // giải mã xác thực chữ ký token
        boolean verified = signedJWT.verify(verifier);
        // lấy Claims id của token
        String tokenId = signedJWT.getJWTClaimsSet().getJWTID();
        // xác thực chữ ký sai or token hết hạn
        if (!(verified && expitytimeToken.after(new Date()))) {
            throw new AppExcetion(ErrorCode.UN_AUTHENTICATED);
        }
        // token đã đăng xuất (đc lưu trong database invalidatedToken thì ko có quyền
        // truy cập )
        if (invalidatedTokenRepository.existsById(tokenId)) {
            throw new AppExcetion(ErrorCode.UN_AUTHENTICATED);
        }
        return signedJWT;

    }

    // build scope trong token để thêm role thực hiện Authorization
    @Override
    public String buildScope(User user) {
        StringJoiner stringJoiner = new StringJoiner(" "); // nối chuỗi lại với nhau vì role trong token cách nhau bằng
                                                           // " " nên dùng " "
        if (!CollectionUtils.isEmpty(user.getRoles())) {
            user.getRoles().forEach((role) -> {
                stringJoiner.add("ROLE_" + role.getName());
                if (!CollectionUtils.isEmpty(role.getPermissions())) {
                    role.getPermissions().forEach((Permission) -> {
                        stringJoiner.add(Permission.getName());
                    });
                }

            });
        }
        return stringJoiner.toString();
    }

    @Override
    public void logout(InvalidatedTokenRequest invalidatedTokenRequest) throws ParseException, JOSEException {
        SignedJWT signedJWT = this.verifierToken(invalidatedTokenRequest.getToken());
        // lấy Claims id token
        String jwtTokenId = signedJWT.getJWTClaimsSet().getJWTID();
        // lấy Claims thời gian hết hạn token
        Date expitytimeToken = signedJWT.getJWTClaimsSet().getExpirationTime();

        InvalidatedToken invalidatedToken = InvalidatedToken.builder()
                .id(jwtTokenId)
                .expiryTime(expitytimeToken)
                .build();

        invalidatedTokenRepository.save(invalidatedToken);

    }

    @Override
    public RefreshTokenResponse refreshToken(RefreshTokenRequest request) throws ParseException, JOSEException {
        SignedJWT signedJWT = verifierToken(request.getToken());
        String idToken = signedJWT.getJWTClaimsSet().getJWTID();
        Date expitytimeToken = signedJWT.getJWTClaimsSet().getExpirationTime();
        // vô hiệu hóa token
        InvalidatedToken invalidatedToken = InvalidatedToken.builder()
                .id(idToken)
                .expiryTime(expitytimeToken)
                .build();
        invalidatedTokenRepository.save(invalidatedToken);
        // cấp lại token cho user
        String username = signedJWT.getJWTClaimsSet().getSubject();
        User user = userRepository.findByUsername(username).orElseThrow(()->{
            return new AppExcetion(ErrorCode.UN_AUTHENTICATED);
        });
        String newToken = this.genToken(user);
        return RefreshTokenResponse.builder()
        .token(newToken)
        .authenticated(true)
        .build();

    }

}
