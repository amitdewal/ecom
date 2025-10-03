package com.example.securitydemo.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.example.securitydemo.jwt.AuthEntryPointJwt;
import com.example.securitydemo.jwt.AuthTokenFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

	@Autowired
	private DataSource dataSource;

	@Autowired
	private AuthEntryPointJwt unAuthorizeHandler;
	

//	public SecurityConfig(DataSource dataSource, AuthEntryPointJwt unAuthorizeHandler) {
//		super();
//		this.dataSource = dataSource;
//		this.unAuthorizeHandler = unAuthorizeHandler;
////		this.authTokenFilter=authTokenFilter;
//	}

	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests.requestMatchers("/h2-console/**").permitAll()
				.requestMatchers("/signin").permitAll()
				.anyRequest().authenticated());
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//		http.formLogin(withDefaults());
//		http.httpBasic(withDefaults());

		http.exceptionHandling(exception -> exception.authenticationEntryPoint(unAuthorizeHandler));

		http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
		http.csrf(csrf -> csrf.disable());
		return http.build();
	}

//	@Bean
//	public UserDetailsService userDetailsService() {
//		UserDetails user1 = User.withUsername("user1").password(passwordEncoder().encode("password1")).roles("USER")
//				.build();
//
//		UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("admin")).roles("ADMIN")
//				.build();
//
//		JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
//		userDetailsManager.createUser(user1);
//		userDetailsManager.createUser(admin);
//		return userDetailsManager;
////		return new InMemoryUserDetailsManager(user1,admin);
//	}
	
	  @Bean
	    public UserDetailsService userDetailsService(DataSource dataSource) {
	        return new JdbcUserDetailsManager(dataSource);
	    }

	 @Bean
	    public CommandLineRunner initData(UserDetailsService userDetailsService) {
	        return args -> {
	            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
	            UserDetails user1 = User.withUsername("user1")
	                    .password(passwordEncoder().encode("password1"))
	                    .roles("USER")
	                    .build();
	            UserDetails admin = User.withUsername("admin")
	                    //.password(passwordEncoder().encode("adminPass"))
	                    .password(passwordEncoder().encode("adminPass"))
	                    .roles("ADMIN")
	                    .build();

	            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
	            userDetailsManager.createUser(user1);
	            userDetailsManager.createUser(admin);
	        };
	    }

	@Bean
	public PasswordEncoder passwordEncoder() {

		return new BCryptPasswordEncoder();

	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

}
