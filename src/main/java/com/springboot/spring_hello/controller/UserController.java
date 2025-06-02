package com.springboot.spring_hello.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.spring_hello.DTO.Request.UserCreationRequest;
import com.springboot.spring_hello.DTO.Request.UserUpdateRequest;
import com.springboot.spring_hello.DTO.response.ApiResponse;
import com.springboot.spring_hello.DTO.response.UserResponse;
import com.springboot.spring_hello.entitys.User;
import com.springboot.spring_hello.service.interfaces.UserService;

import jakarta.validation.Valid;


@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("/create")
    public ApiResponse<UserResponse> createUser(@RequestBody @Valid UserCreationRequest request) {
        ApiResponse apiResponse = new ApiResponse<>();
        apiResponse.setResult(userService.createUser(request));
        return apiResponse;
        

    }

    @GetMapping("/getlist")
    public ApiResponse<List<UserResponse>> getListUser() {
        // in ra user name và role khi vào endpoint 
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("username: " + authentication.getName());
        authentication.getAuthorities().forEach(GrantedAuthority->{
            System.out.println("role "+GrantedAuthority.getAuthority());
        });
        
        return ApiResponse.<List<UserResponse>>builder()
        .result(userService.getUser())
        .code(200)
        .build();
    }
    @GetMapping("/get/{userid}")
    public ApiResponse<UserResponse> getUser(@PathVariable("userid") String userId) {
        return ApiResponse.<UserResponse>builder()
        .code(200)
        .result(userService.getUserMaper(userId))
        .build();
    }

    // lấy thông tin của người đăng nhập qua SecurityContextHolder
    @GetMapping("/get/myinfo")
    public ApiResponse<UserResponse> getMyInfo() {
        return ApiResponse.<UserResponse>builder()
        .code(200)
        .result(userService.getMyInfo())
        .build();
    }

    @PutMapping("/update/{userid}")
    ApiResponse<UserResponse> updateUser(@PathVariable("userid") String id, @RequestBody UserUpdateRequest userUpdateRepuest) {
        return ApiResponse.<UserResponse>builder()
        .code(200)
        .result(userService.updatUserMapper(id, userUpdateRepuest))
        .build();
    }
    @DeleteMapping("/delete/{userid}")
    public ApiResponse<String> deleteUser(@PathVariable("userid") String id){
        userService.deleteUser(id);
        return ApiResponse.<String>builder()
        .code(200)
        .result("đã xóa user có id ")
        .message(id)
        .build();
    }

}