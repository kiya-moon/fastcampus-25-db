package com.onion.backend.service;


import com.onion.backend.dto.SignUpUser;
import com.onion.backend.entity.User;
import com.onion.backend.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // 유저 조회 메서드
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    // 유저 생성 메서드
    public User createUser(SignUpUser signUpUser) {
        User user = new User();
        user.setUsername(signUpUser.getUsername());
        user.setPassword(passwordEncoder.encode(signUpUser.getPassword()));
        user.setEmail(signUpUser.getEmail());

        return userRepository.save(user); // 유저 저장
    }

    // 유저 삭제 메소드
    public void deleteUser(Long id) {
        userRepository.deleteById(id);  // 존재하는 유저를 삭제
    }

}
