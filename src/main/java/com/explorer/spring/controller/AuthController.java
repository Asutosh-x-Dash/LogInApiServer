package com.explorer.spring.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.explorer.spring.processor.UserAuthenticator;
import com.explorer.spring.request.LoginRequest;
import com.explorer.spring.request.SignupRequest;

import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600) 
@RestController 
@RequestMapping("/api/auth") 
public class AuthController {
	private final UserAuthenticator authenticator;
	
	@Autowired
	public AuthController(UserAuthenticator authenticator) {
		this.authenticator = authenticator;
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		return authenticator.registerUser(signUpRequest);
	}
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		return authenticator.signIn(loginRequest);
	}

}
