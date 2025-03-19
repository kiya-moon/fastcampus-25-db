package com.onion.backend.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // String은 보통 null을 쓰지 않음. "" 사용
    @Column(nullable = false)
    private String username; // 로그인 ID

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email;

    @Column
    private LocalDateTime lastLogin; // 최근 로그인 시간

    // 시간을 NOW()로 넣으면 서버 시간을 따라가다가 동시성 문제가 발생하기도 함
    @CreatedDate
    @Column(insertable = true)
    private LocalDateTime createDate; // 회원 가입일 (수정 불가)

    @LastModifiedDate
    private LocalDateTime updateDate; // 유저 정보 수정일 (자동 업데이트)
}

