package com.springboot.spring_hello.configuration;

import java.util.HashSet;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.springboot.spring_hello.entitys.User;
import com.springboot.spring_hello.enums.Roles;
import com.springboot.spring_hello.repository.UserRepository;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Configuration
@RequiredArgsConstructor // tạo contructor để khởi tạo toàn bộ các thuộc tính đc inject từ Autowired ( khi dùng có thể bỏ autowire để code tường minh hơn )
@FieldDefaults(level = AccessLevel.PRIVATE,makeFinal = true)
public class ApplicationInitConfig {

    PasswordEncoder passwordEncoder;
    // tao admin khi khoi dong app lan đau 
    @Bean
    ApplicationRunner applicationRunner(UserRepository userRepository){
        return args->{
            // kiem tra co tk admin chua 
            if(userRepository.findByUsername("admin").isEmpty()){
                HashSet<String> roles = new HashSet<>();
                roles.add(Roles.ADMIN.toString());
                User user = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin"))
                // .roles(roles)
                .build();

                userRepository.save(user);
                System.out.println("đã tạo tk admin");
            }else{
                System.out.println("tài khoản admin đã tồn tại");
            }
        };
    }
}
