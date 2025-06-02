package com.springboot.spring_hello.service.interfaces;

import java.util.List;

import com.springboot.spring_hello.DTO.Request.RoleRequest;
import com.springboot.spring_hello.DTO.response.RoleResponse;

public interface RoleService {
    RoleResponse create(RoleRequest request);
   List<RoleResponse> getAll();
    void delete(String nameRole);
}
