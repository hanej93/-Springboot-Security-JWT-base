package com.cos.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.Users;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// /login 요청해서 username, password 전송하면 (post) 위의 필터가 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private final AuthenticationManager authenticationManager;

	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		System.out.println("JwtAuthenticationFilter: 로그인 시도중");
		
		// 1. username, password 받아서
		try {
//			BufferedReader br = request.getReader();
//			
//			String input = null;
//			while((input = br.readLine()) != null) {
//				System.out.println(input);
//			}
			
			ObjectMapper om = new ObjectMapper();
			Users user = om.readValue(request.getInputStream(), Users.class);
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// PrincipalDetailsService loadUsrByUsername() 함수 실행된 후 정상이면 authentication이 리턴됨
			// database에 있는 username과 password가 일치한다.
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			
			// 값을 꺼내서 확인해봄
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			
			System.out.println("정상적으로 로그인 되었는지 확인: " + principalDetails.getUser().getUsername());
			
			// authentication 객체가 session 영역에 저장해야 함 그 방빕어 return
			// 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 거고
			// 굳이 JWT 토큰을 사용하면서 세션을 만들 이유는 없지만, 단지 권한 처리때문에 session에 넣어줌
			
			return authentication;
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수 실행
	// JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		System.out.println("successfulAuthentication 실행됨, 로그인이 되었음");
		
		
		super.successfulAuthentication(request, response, chain, authResult);
	}
}
