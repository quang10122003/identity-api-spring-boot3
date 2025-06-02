package com.springboot.spring_hello.service.implement;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.springboot.spring_hello.DTO.Request.UserCreationRequest;
import com.springboot.spring_hello.DTO.Request.UserUpdateRequest;
import com.springboot.spring_hello.DTO.response.UserResponse;
import com.springboot.spring_hello.entitys.Role;
import com.springboot.spring_hello.entitys.User;
import com.springboot.spring_hello.enums.Roles;
import com.springboot.spring_hello.exception.AppExcetion;
import com.springboot.spring_hello.exception.ErrorCode;
import com.springboot.spring_hello.mapper.UserMapper;
import com.springboot.spring_hello.repository.RoleRepository;
import com.springboot.spring_hello.repository.UserRepository;
import com.springboot.spring_hello.service.interfaces.UserService;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@Service
@RequiredArgsConstructor // tạo contructor để khởi tạo toàn bộ các thuộc tính đc inject từ Autowired (
                         // khi dùng có thể bỏ autowire để code tường minh hơn )
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserServiceImpl implements UserService {

    UserRepository userRepository;

    UserMapper userMapper;

    PasswordEncoder passwordEncoder;

    RoleRepository roleRepository;

    @Override
    public UserResponse createUser(UserCreationRequest request) {
        try {
            if (userRepository.existsByUsername(request.getUsername())) {
                throw new AppExcetion(ErrorCode.USER_EXISTED);
            }

            // User user = new User();
            // user.setUsername(request.getUsername());
            // user.setPassword(request.getPassword());
            // user.setFirstName(request.getFirstName());
            // user.setLastName(request.getLastName());
            // user.setNgaySinh(request.getNgaySinh());

            // dùng mapper
            User user = userMapper.toUser(request);
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            List<Role> listRole = roleRepository.findAllById(List.of("USER"));
            user.setRoles(new HashSet<>(listRole));
            return userMapper.toUserResponse(userRepository.save(user));

        } catch (RuntimeException e) {
            // Ghi log nếu cần
            System.out.println("Lỗi: " + e.getMessage());
            // Có thể ném lại lỗi để controller xử lý
            throw e;
        } catch (Exception e) {
            // Trường hợp lỗi khác ngoài RuntimeException
            System.out.println("Lỗi không xác định: " + e.getMessage());
            throw new RuntimeException("Có lỗi xảy ra trong quá trình tạo user");
        }
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')") // phân theo quyền
    // phân theo role thì @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @Override
    public List<UserResponse> getUser() {
        return userRepository.findAll().stream().map((user) ->{
            return userMapper.toUserResponse(user);
        } ).toList();
    }

    @Override
    public User getUser(String id) {
        return userRepository.findById(id).orElseThrow(() -> {
            return new AppExcetion(ErrorCode.NO_USER);
        });
    }

    @PostAuthorize("(authentication.name == 'admin') or (returnObject.username == authentication.name)") // kiểm tra quyền truy cập sau khi chạy method nếu ko có quyền thì k có phép method trả về nhưng method vẫn chạy trái vs PreAuthorize
    // returnObject ở đây chính là biến trả về của method 
    // chi cho phép user lấy đc thông tin của chính mình với và admin lấy đc hết  @PostAuthorize("(authentication.name == 'admin') or (returnObject.username == authentication.name)")
    @Override
    public UserResponse getUserMaper(String id) {
        return userMapper.toUserResponse(userRepository.findById(id).orElseThrow(() -> {
            return new AppExcetion(ErrorCode.NO_USER);
        }));
    }

    // k dung mapper tra về etity
    @Override
    public User updatUser(String id, UserUpdateRequest userUpdateRepuest) {
        User user = this.getUser(id);

        // user.setPassword(userUpdateRepuest.getPassword());
        // user.setFirstName(userUpdateRepuest.getFirstName());
        // user.setLastName(userUpdateRepuest.getLastName());
        // user.setNgaySinh(userUpdateRepuest.getNgaySinh());

        // mapper
        userMapper.updateUser(user, userUpdateRepuest);
        return userRepository.save(user);
    }

    // dung mapper tra về DTO
    @Override
    public UserResponse updatUserMapper(String id, UserUpdateRequest userUpdateRepuest) {
        User user = this.getUser(id);
        userMapper.updateUser(user, userUpdateRepuest);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        List<Role> listRole = roleRepository.findAllById(userUpdateRepuest.getRoles());
        user.setRoles(new HashSet<>(listRole));
        return userMapper.toUserResponse(userRepository.save(user));

    }

    @Override
    public void deleteUser(String id) {
        userRepository.deleteById(id);
    }

    // lấy về thông tin đăng nhập của chính mình từ SecurityContextHolder 
    @Override
    public UserResponse getMyInfo() {
        // khi request thành công thì SecurityContextHolder sẽ đc spring lưu thông tin của user đăng nhập 
        var contextUser =  SecurityContextHolder.getContext(); // get user hiện tại 
        System.out.println(contextUser);
        String username = contextUser.getAuthentication().getName(); // tên của user đăng nhập theo token ở trường subject

        User byUser =  userRepository.findByUsername(username).orElseThrow(()->{
            return new AppExcetion(ErrorCode.USER_NO_EXISTED);
        });
        return userMapper.toUserResponse(byUser);
    }

}
