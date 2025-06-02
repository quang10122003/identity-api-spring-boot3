package com.springboot.spring_hello.DTO.response;

import java.time.LocalDate;
import java.util.Set;

import com.springboot.spring_hello.entitys.Role;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserResponse {
    String id;
    String username;
    String firstName;
    String lastName;
    LocalDate ngaySinh;
    Set<RoleResponse> roles;
}
