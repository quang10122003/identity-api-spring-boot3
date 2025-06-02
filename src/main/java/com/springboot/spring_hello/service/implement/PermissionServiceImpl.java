package com.springboot.spring_hello.service.implement;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import com.springboot.spring_hello.DTO.Request.PermissionRequest;
import com.springboot.spring_hello.DTO.response.PermissionResponse;
import com.springboot.spring_hello.entitys.Permission;
import com.springboot.spring_hello.mapper.PermissionMapper;
import com.springboot.spring_hello.repository.PermissionRepository;
import com.springboot.spring_hello.service.interfaces.PermissionSevice;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class PermissionServiceImpl implements PermissionSevice {
    PermissionRepository permissionRepository;
    PermissionMapper permissionMapper;

    @Override
    public PermissionResponse create(PermissionRequest request){
        Permission permission = permissionMapper.toPermission(request);
        permission = permissionRepository.save(permission);
        return permissionMapper.toPermissionResponse(permission);
    }

    @Override
    public List<PermissionResponse> getAll(){
        var permissions = permissionRepository.findAll();
        return permissions.stream().map(permissionMapper::toPermissionResponse).toList();
    }
    @Override
    public void delete(String permission){
        permissionRepository.deleteById(permission);
    }
}