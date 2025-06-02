package com.springboot.spring_hello.controller;

import java.util.List;

import org.mapstruct.Mapping;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.spring_hello.DTO.Request.PermissionRequest;
import com.springboot.spring_hello.DTO.response.ApiResponse;
import com.springboot.spring_hello.DTO.response.PermissionResponse;
import com.springboot.spring_hello.service.interfaces.PermissionSevice;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@RestController
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/permission")
@RequiredArgsConstructor
public class PermissionController {

    PermissionSevice permissionSevice;

    @PostMapping("/create")
    ApiResponse<PermissionResponse> create(@RequestBody PermissionRequest request){
        return ApiResponse.<PermissionResponse>builder()
                .result(permissionSevice.create(request))
                .build();
    }

    @GetMapping("/getall")
    ApiResponse<List<PermissionResponse>> getAll(){
        return ApiResponse.<List<PermissionResponse>>builder()
                .result(permissionSevice.getAll())
                .build();
    }

    @DeleteMapping("/{permission}")
    ApiResponse<Void> delete(@PathVariable String permission){
        permissionSevice.delete(permission);
        return ApiResponse.<Void>builder().build();
    }
}
