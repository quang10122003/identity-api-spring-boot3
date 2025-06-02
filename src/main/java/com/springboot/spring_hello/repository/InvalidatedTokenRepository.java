package com.springboot.spring_hello.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.springboot.spring_hello.entitys.InvalidatedToken;
@Repository
public interface InvalidatedTokenRepository extends JpaRepository<InvalidatedToken, String>{
    boolean existsById(String id);
}
