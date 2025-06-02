package com.springboot.spring_hello.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.springboot.spring_hello.DTO.response.RoleResponse;
import com.springboot.spring_hello.entitys.Permission;
import com.springboot.spring_hello.entitys.Role;

@Repository
public interface PermissionRepository extends JpaRepository<Permission,String> {
}
