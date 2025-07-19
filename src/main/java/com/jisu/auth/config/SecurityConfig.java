package com.jisu.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order; // Import Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 애플리케이션의 기본 보안 설정을 구성합니다.
     * 모든 요청은 인증을 필요로 하며, 폼 기반 로그인을 사용합니다.
     */
    @Bean
    @Order(2) // 인가 서버 필터 체인 다음에 적용되도록 순서를 지정합니다.
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                // 기본 제공되는 폼 로그인 페이지를 사용합니다.
                .formLogin(withDefaults());
        return http.build();
    }

    /**
     * 인메모리 방식의 사용자 저장소를 설정합니다.
     * 테스트를 위해 'user'라는 이름과 'password'라는 비밀번호를 가진 사용자를 생성합니다.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }

    /**
     * 비밀번호를 안전하게 암호화하기 위한 PasswordEncoder를 빈으로 등록합니다.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}