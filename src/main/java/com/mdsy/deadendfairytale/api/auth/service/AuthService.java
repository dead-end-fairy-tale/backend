package com.mdsy.deadendfairytale.api.auth.service;

import com.mdsy.deadendfairytale.api.auth.dto.request.AuthRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.response.AuthResponseDTO;
import com.mdsy.deadendfairytale.api.exception.DuplicateUserException;
import com.mdsy.deadendfairytale.api.exception.LoginFailException;
import com.mdsy.deadendfairytale.api.model.entity.User;
import com.mdsy.deadendfairytale.api.repository.UserRepository;
import com.mdsy.deadendfairytale.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public boolean Signup(AuthRequestDTO requestDTO) {
        if(userRepository.existsById(requestDTO.getUsername())) {
            throw new DuplicateUserException("이미 가입된 유저명입니다.");
        }

        User user = User.builder()
                .userId(requestDTO.getUsername())
                .password(passwordEncoder.encode(requestDTO.getPassword()))
                .createdAt(LocalDateTime.now())
                .build();

        userRepository.save(user);

        return true;
    }

    public AuthResponseDTO login(AuthRequestDTO requestDTO) {
        Optional<User> findUser = userRepository.findById(requestDTO.getUsername());

        if(findUser.isPresent()) {
            User user = findUser.get();
            if(!passwordEncoder.matches(requestDTO.getPassword(), user.getPassword())) {
                throw new LoginFailException("아이디 혹은 비밀번호가 일치하지 않습니다!");
            }
            String accessToken = JwtUtil.generateAccessToken(user.getUserId());
            String refreshToken = JwtUtil.generateRefreshToken(user.getUserId());

            user.setRefreshToken(refreshToken);
            userRepository.save(user);

            return AuthResponseDTO.builder()
                    .username(user.getUserId())
                    .token(accessToken)
                    .build();
        } else {
            throw new LoginFailException("아이디 혹은 비밀번호가 일치하지 않습니다!");
        }
    }
}
