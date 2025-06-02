package com.springboot.spring_hello.DTO.Request;

import java.time.LocalDate;

import com.springboot.spring_hello.validator.NgaySinhContraint;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldDefaults;
// @Getter
// @Setter
@Data
@Builder  //tạo đối tượng nhanh hơn
@AllArgsConstructor
@NoArgsConstructor
// @FieldDefaults(level = AccessLevel.PRIVATE)   không khai báo phạm vi mặc định là private 
public class UserCreationRequest {

    @Size(min = 3, message ="USER_NAME_MIN" )
    private String username;

    @NotBlank(message = "NO_PASSWORD")
    @Size(min = 6, message = "PASSWORD_MIN")
    private String password;
    private String firstName;
    private String lastName;
    // min là 18 anotion custom 
    @NgaySinhContraint(min = 18)
    private LocalDate ngaySinh;

    
}