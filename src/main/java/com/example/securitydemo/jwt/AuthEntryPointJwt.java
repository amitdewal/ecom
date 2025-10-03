package com.example.securitydemo.jwt;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
//import sun.jvm.hotspot.tools.FinalizerInfo;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

	private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
//		Enumeration<String> headerNames = request.getHeaderNames();
//		if (headerNames != null) {
//		    while (headerNames.hasMoreElements()) {
//		        String name = headerNames.nextElement();
//		        logger.debug("Header: {} = {}", name, request.getHeader(name));
//		    }
//		} else {
//		    logger.debug("No headers present");
//		}
//
//		logger.error("Unauthorized error: {}", authException.getMessage());
//
//		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);// 401
//		final Map<String, Object> body = new HashMap<>();
//		body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
//		body.put("errors", "Unauthorized");
//		body.put("message", authException.getMessage());
//		body.put("path", request.getServletPath());// api path
//
//		final ObjectMapper mapper = new ObjectMapper();
//		mapper.writeValue(response.getOutputStream(), body);
//
	}

}
