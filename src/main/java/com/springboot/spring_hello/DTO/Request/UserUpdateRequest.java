package com.springboot.spring_hello.DTO.Request;

import java.time.LocalDate;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserUpdateRequest {
    private String password;
    private String firstName;
    private String lastName;
    private LocalDate ngaySinh;
    Set<String> roles;
    

}
