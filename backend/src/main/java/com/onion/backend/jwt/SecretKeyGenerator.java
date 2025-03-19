package com.onion.backend.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Base64;

// JwtUtil에 쓰이는 secretKey 생성에 필요한 파일
// 단독 실행 시 secretKey를 얻을 수 있음
public class SecretKeyGenerator {
    public static void main(String[] args) {
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String secretKey = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("Generated Secret Key: " + secretKey);
    }
}
