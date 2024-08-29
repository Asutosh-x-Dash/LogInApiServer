package com.explorer.spring.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600) 
@RestController 
@RequestMapping("/api/test") 
public class TestController {

	/**
	 * Public endpoint that can be accessed without any authentication.
	 *
	 * @return A string message indicating public content.
	 */
	@GetMapping("/all") 
	public String allAccess() {
		return "Public Content."; 
	}

	/**
	 * Endpoint accessible only to users with USER, MODERATOR, or ADMIN roles.
	 *
	 * @return A string message indicating user content.
	 */
	@GetMapping("/user") 
	@PreAuthorize("hasRole('USER') or " +
			"hasRole('MODERATOR') or " +
			"hasRole('ADMIN')")
	public String userAccess() {
		return "User Content."; 
	}

	/**
	 * Endpoint accessible only to users with the MODERATOR role.
	 *
	 * @return A string message indicating moderator board content.
	 */
	@GetMapping("/mod") 
	@PreAuthorize("hasRole('MODERATOR')") 
	public String moderatorAccess() {
		return "Moderator Board."; 
	}

	/**
	 * Endpoint accessible only to users with the ADMIN role.
	 *
	 * @return A string message indicating admin board content.
	 */
	@GetMapping("/admin") 
	@PreAuthorize("hasRole('ADMIN')") 
	public String adminAccess() {
		return "Admin Board."; 
	}
}
