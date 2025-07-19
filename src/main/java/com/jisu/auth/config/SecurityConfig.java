package com.jisu.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order; // Import Order
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * API 엔드포인트(/api/**)를 위한 보안 필터 체인입니다.
     * 이 필터 체인은 리소스 서버 역할을 하며, Bearer 토큰을 검증합니다.
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2) // 인가 서버 필터 체인 다음에 적용되도록 순서를 지정합니다.
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. 이 필터 체인은 /api/로 시작하는 경로에만 적용됩니다.
                .securityMatcher("/api/**")
                // 2. 모든 /api/** 요청은 인증을 필요로 합니다.
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                // 3. Bearer 토큰(JWT)을 검증하는 리소스 서버로 설정합니다.
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                // 4. API 서버는 상태가 없으므로(stateless) CSRF 보호를 비활성화합니다.
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /**
     * 웹 UI(로그인 페이지 등)를 위한 기본 보안 설정을 구성합니다.
     * 이 필터 체인은 다른 필터 체인에서 처리하지 않은 나머지 모든 요청을 담당합니다.
     */
    @Bean
    @Order(3) // 가장 낮은 우선순위를 가집니다.
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                // 모든 요청은 인증을 필요로 합니다.
                .anyRequest().authenticated())
                // 인증되지 않은 사용자를 위한 폼 기반 로그인을 제공합니다.
                .formLogin(configure -> configure
                    .successHandler(new SavedRequestAwareAuthenticationSuccessHandler()));
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