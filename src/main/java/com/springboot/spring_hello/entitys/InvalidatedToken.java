package com.springboot.spring_hello.entitys;


import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

// class emtity ánh xạ bảng lưu id của token để vô hiệu hóa token 
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Entity
@Table(name="InvalidatedToken")
public class InvalidatedToken {
    @Id
    String id;
    Date expiryTime; // thời gian hết hạn 

}