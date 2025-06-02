package com.springboot.spring_hello.mapper;

import org.mapstruct.Mapper;

import com.springboot.spring_hello.DTO.Request.PermissionRequest;
import com.springboot.spring_hello.DTO.response.PermissionResponse;
import com.springboot.spring_hello.entitys.Permission;

@Mapper(componentModel = "spring")
public interface PermissionMapper {
    Permission toPermission(PermissionRequest request);
    
    PermissionResponse toPermissionResponse(Permission permission);
}