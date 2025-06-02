package com.springboot.spring_hello.service.interfaces;

import java.util.List;

import com.springboot.spring_hello.DTO.Request.UserCreationRequest;
import com.springboot.spring_hello.DTO.Request.UserUpdateRequest;
import com.springboot.spring_hello.DTO.response.UserResponse;
import com.springboot.spring_hello.entitys.User;

public interface UserService {
    UserResponse createUser(UserCreationRequest reqest);
    List<UserResponse> getUser();
    User getUser(String id);
    User updatUser(String id,UserUpdateRequest userUpdateRepuest);
    UserResponse updatUserMapper(String id,UserUpdateRequest userUpdateRepuest);
    void deleteUser(String id);
    UserResponse getUserMaper(String id);
    UserResponse getMyInfo();
}
