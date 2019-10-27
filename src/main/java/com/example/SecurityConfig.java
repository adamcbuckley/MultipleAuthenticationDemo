package com.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	/**
	 * /user/**
	 */
	@Configuration
	@Order(1)
	public static class UserConfigurationAdapter extends WebSecurityConfigurerAdapter {

		@Bean
		public UserDetailsService userDetailsService() {
			final InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

			manager.createUser(User
					.withUsername("user")
					.password(encoder().encode("password"))
					.roles("USER").build());

			// Can be used to gain access to the admin section, if SAML isn't available
			manager.createUser(User
					.withUsername("admin")
					.password(encoder().encode("password"))
					.roles("ADMIN").build());

			return manager;
		}

		@Bean
		public PasswordEncoder encoder() {
			return new BCryptPasswordEncoder();
		}

		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.antMatcher("/user/**")
					.authorizeRequests()
						.anyRequest().hasRole("USER")
						.and()
					.formLogin()
						.loginPage("/login.html")
						.loginProcessingUrl("/user/login")
						.failureUrl("/login.html?error=Login+failed")
						.defaultSuccessUrl("/user/user-profile")
						.and()
					.logout()
						.logoutUrl("/user/logout")
						.logoutSuccessUrl("/")
						.deleteCookies("JSESSIONID")
						.and()
					.csrf().disable();
			// @formatter:on
		}
	}


	/**
	 * Define /guest/**
	 */
	@Configuration
	@Order(2)
	public static class PublicConfigurationAdapter extends WebSecurityConfigurerAdapter {
		protected void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/guest/**")
					.authorizeRequests()
					.anyRequest().permitAll();
		}
	}


	/**
	 * Define /admin/**
	 */
	@Configuration
	@Order(3)
	public static class AdminConfigurationAdapter extends WebSecurityConfigurerAdapter {

		@Value("${security.saml2.metadata-url}")
		String metadataUrl;

		@Value("${server.ssl.key-alias}")
		String keyAlias;

		@Value("${server.ssl.key-store-password}")
		String password;

		@Value("${server.port}")
		String port;

		@Value("${server.ssl.key-store}")
		String keyStoreFilePath;


		/**
		 * Define SAML user details service
		 */
		@Bean
		public static SAMLUserDetailsService samlUserDetailsService() {
			return credential -> {
				final String userId = credential.getNameID().getValue();
				final String[] groups = credential.getAttributeAsStringArray("GROUPS");
				final List<GrantedAuthority> authorities = new ArrayList<>();
				for (final String group : groups) {
					authorities.add(new SimpleGrantedAuthority(group));
				}
				return new User(userId, "", authorities);
			};
		}


		@Override
		protected void configure(HttpSecurity http) throws Exception {

			http.authorizeRequests()
					.antMatchers("/saml*").permitAll()
					.antMatchers("/admin/**").hasRole("ADMIN");

			/*
			 * TODO: This code doesn't work... the  /saml urls throw a 404 Not Found
			 * http.antMatcher("/admin/**").apply(saml()) ...
			 */

			// @formatter:off
			http.apply(saml())
					.userDetailsService(samlUserDetailsService())
					.serviceProvider()
						.keyStore()
							.storeFilePath(this.keyStoreFilePath)
							.password(this.password)
							.keyname(this.keyAlias)
							.keyPassword(this.password)
							.and()
						.protocol("https")
						.hostname(String.format("%s:%s", "localhost", this.port))
						.basePath("/")
						.and()
					.identityProvider().metadataFilePath(this.metadataUrl);
			// @formatter:on
		}
	}
}
