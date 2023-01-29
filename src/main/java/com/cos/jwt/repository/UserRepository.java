package com.cos.jwt.repository;


import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.jwt.model.Users;

public interface UserRepository extends JpaRepository<Users, Long>{

	public Users findByUsername(String username);
	
}
