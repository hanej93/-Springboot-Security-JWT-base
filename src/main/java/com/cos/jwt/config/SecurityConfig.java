package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig  {
	
	private final CorsFilter corsFilter;
	private final UserRepository userRepository;
	
	@Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
//        	.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class) // 클래스에 걸린 필터이전에 실행
	        .csrf().disable()
	        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다.(stateless)
	        .and()
	        .addFilter(corsFilter) // @CrossOrgin(인증 x), 시큐리티 필터에 등록 인증(o)
	    	.formLogin().disable() // formLogin을 안쓰겠다.
	    	.httpBasic().disable() // 요청시 헤더에 Authorization(id,pw)를 담아서 보냄 -> 사용 안하겠다. // id,pw 대신 토큰 사용 -> Bearer 방식
	    	.apply(new MyCustomDsl())
//	    	.addFilter(new JwtAuthenticationFilter()) // AuthenticationManager
	    	.and()
	    	.authorizeRequests(authroize -> authroize
	    			.antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
					.antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
					.antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
					.anyRequest().permitAll());
        
        return http.build();
    }
	
	
	public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
			http
					.addFilter(corsFilter)
					.addFilter(new JwtAuthenticationFilter(authenticationManager))
					.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository))
					;
		}
	}

}
