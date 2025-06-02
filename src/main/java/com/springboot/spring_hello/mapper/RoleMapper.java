package com.springboot.spring_hello.mapper;


import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import com.springboot.spring_hello.DTO.Request.RoleRequest;
import com.springboot.spring_hello.DTO.response.RoleResponse;
import com.springboot.spring_hello.entitys.Role;

@Mapper(componentModel = "spring",uses = PermissionMapper.class)
public interface RoleMapper {
    @Mapping(target = "permissions", ignore = true)

    Role toRole(RoleRequest request);

    RoleResponse toRoleResponse(Role role);
}