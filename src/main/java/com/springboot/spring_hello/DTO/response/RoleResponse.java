package com.springboot.spring_hello.DTO.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Set;

import com.springboot.spring_hello.entitys.Permission;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RoleResponse {
    String name;
    String description;
    Set<PermissionResponse> permissions;
}