package com.explorer.spring.security.jwt;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.explorer.spring.security.services.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTUtil {
	
	private static final Logger logger = LoggerFactory.getLogger(JWTUtil.class);

	  @Value("${jwtSecret}")
	  private String jwtSecret;

	  @Value("${jwtExpirationMs}")
	  private int jwtExpirationMs;

	  /**
	   * Generate a JWT token based on the provided authentication.
	   *
	   * @param authentication The authentication object containing user details.
	   * @return The generated JWT token as a string.
	   */
	  public String generateJwtToken(Authentication authentication) {
	    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

	    // Build and return the JWT token
	    return Jwts.builder()
	            .setSubject((userPrincipal.getUsername()))
	            .setIssuedAt(new Date())
	            .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
	            .signWith(key(), SignatureAlgorithm.HS256)
	            .compact();
	  }
	  
	  /**
	   * Create a signing key from the JWT secret.
	   *
	   * @return The signing key as a Key object.
	   */
	  private Key key() {
	    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
	  }

	  /**
	   * Extract the username from the given JWT token.
	   *
	   * @param token The JWT token.
	   * @return The username extracted from the token.
	   */
	  public String getUserNameFromJwtToken(String token) {
	    return Jwts.parserBuilder().setSigningKey(key()).build()
	            .parseClaimsJws(token).getBody().getSubject();
	  }

	  /**
	   * Validate the given JWT token.
	   *
	   * @param authToken The JWT token to validate.
	   * @return True if the token is valid, false otherwise.
	   */
	  public boolean validateJwtToken(String authToken) {
	    try {
	      Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
	      return true;
	    } catch (MalformedJwtException e) {
	      logger.error("Invalid JWT token: {}", e.getMessage());
	    } catch (ExpiredJwtException e) {
	      logger.error("JWT token is expired: {}", e.getMessage());
	    } catch (UnsupportedJwtException e) {
	      logger.error("JWT token is unsupported: {}", e.getMessage());
	    } catch (IllegalArgumentException e) {
	      logger.error("JWT claims string is empty: {}", e.getMessage());
	    }

	    return false;
	  }

}
