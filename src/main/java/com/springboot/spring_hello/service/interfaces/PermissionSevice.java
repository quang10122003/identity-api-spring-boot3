package com.springboot.spring_hello.service.interfaces;

import java.util.List;

import com.springboot.spring_hello.DTO.Request.PermissionRequest;
import com.springboot.spring_hello.DTO.response.PermissionResponse;

public interface PermissionSevice {
    PermissionResponse create(PermissionRequest request);
    List<PermissionResponse>  getAll();
    void delete(String namePermission);
    
}
