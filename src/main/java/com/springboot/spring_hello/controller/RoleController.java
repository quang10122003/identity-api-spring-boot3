package com.springboot.spring_hello.controller;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.spring_hello.DTO.Request.RoleRequest;
import com.springboot.spring_hello.DTO.response.ApiResponse;
import com.springboot.spring_hello.DTO.response.RoleResponse;
import com.springboot.spring_hello.service.interfaces.RoleService;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@RestController
@RequestMapping("/role")
@FieldDefaults(level = AccessLevel.PRIVATE,makeFinal = true)
@RequiredArgsConstructor

public class RoleController {
    RoleService roleService;

    @PostMapping("/create")
    public ApiResponse<RoleResponse> create(@RequestBody RoleRequest request){
        
        RoleResponse roleRespone = roleService.create(request);
        return ApiResponse.<RoleResponse>builder()
        .code(200)
        .result(roleRespone)
        .build();
    }

    @GetMapping("/RoleGetAll")
    ApiResponse<List<RoleResponse>> GetAll(){
        return ApiResponse.<List<RoleResponse>>builder()
        .code(200)
        .result(roleService.getAll())
        .build();
    }

    @DeleteMapping("/deleteRole/{nameRole}")
    ApiResponse<Void> deletePermission(@PathVariable("nameRole") String nameRole){
        roleService.delete(nameRole);
        return ApiResponse.<Void>builder()
        .code(200)
        .message("đã xóa thành công role"+nameRole)
        .build();
    }

}
