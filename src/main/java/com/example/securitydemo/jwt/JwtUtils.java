package com.example.securitydemo.jwt;

import java.security.Key;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

	@Value("${spring.app.jwtExpirationMs}")
	private int jwtExpirationMs;

	@Value("${spring.app.jwtSecret}")
	private String jwtSecret;

	// getting JWT from Header
	  public String getJwtFromHeader(HttpServletRequest request) {
	        String bearerToken = request.getHeader("Authorization");
	        logger.debug("Authorization Header: {}", bearerToken);
	        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
	            return bearerToken.substring(7); // Remove Bearer prefix
	        }
	        return null;
	    }


	// generating token from username

	public String genrateTokenfromUsername(UserDetails userDetails) {
		String username = userDetails.getUsername();

		 return Jwts.builder()
	                .subject(username)
	                .issuedAt(new Date())
	                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
	                .signWith(key())
	                .compact();

	}

	// getting username from jwt token
	public String getUserNamefromJWTToken(String token) {
		return Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(token).getPayload().getSubject();

	}

	// generate signing key

	 private Key key() {
	        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
	    }

	// validate jwt token

	public Boolean validatejwtToken(String authToken) {
		try {
			System.out.println("Validate");
			Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
			return true;
		} catch (MalformedJwtException exception) {
			logger.error("Invalid JWT token: {}", exception.getMessage());

		} catch (ExpiredJwtException exception) {
			logger.error("JWT token expired: {}", exception.getMessage());
		} catch (UnsupportedJwtException exception) {
			logger.error("JWT token unsupported: {}", exception.getMessage());
		} catch (IllegalArgumentException exception) {
			logger.error("JWT claims string is empty : {}", exception.getMessage());
		}
		return false;

	}

}
