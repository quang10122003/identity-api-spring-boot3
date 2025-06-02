package com.springboot.spring_hello.mapper;

import com.springboot.spring_hello.DTO.Request.UserCreationRequest;
import com.springboot.spring_hello.DTO.Request.UserUpdateRequest;
import com.springboot.spring_hello.DTO.response.UserResponse;
import com.springboot.spring_hello.entitys.User;

import java.lang.annotation.Target;
import java.util.List;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring",uses = RoleMapper.class)
public interface UserMapper {
    User toUser(UserCreationRequest request);

    // List<UserResponse> toUserResponseList(List<User> users);
    @Mapping(target ="roles",ignore = true )
    void updateUser(@MappingTarget User user, UserUpdateRequest request);

    UserResponse toUserResponse(User user);
}
