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
	 * Define a simple in-memory user database
	 */
	@Bean
	public UserDetailsService userDetailsService() {
		final InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

		manager.createUser(User
				.withUsername("user")
				.password(encoder().encode("userPass"))
				.roles("USER").build());

		manager.createUser(User
				.withUsername("admin")
				.password(encoder().encode("adminPass"))
				.roles("ADMIN").build());

		return manager;
	}

	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}


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


	/**
	 * Define first entry point, /admin/**
	 */
	@Configuration
	@Order(3)
	public static class App1ConfigurationAdapter extends WebSecurityConfigurerAdapter {

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

		@Override
		protected void configure(HttpSecurity http) throws Exception {

			http.authorizeRequests()
					.antMatchers("/saml*").permitAll()
					.antMatchers("/admin/**").hasRole("ADMIN");

			// @formatter:off
			http.apply(saml()).userDetailsService(samlUserDetailsService())
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
				.identityProvider()
				.metadataFilePath(this.metadataUrl);
			// @formatter:on
		}
	}


	/**
	 * Define second entry point, /user/**
	 */
	@Configuration
	@Order(1)
	public static class App2ConfigurationAdapter extends WebSecurityConfigurerAdapter {

		protected void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/user/**")
					.authorizeRequests().anyRequest().hasRole("USER")
					.and().formLogin().loginProcessingUrl("/user/login").failureUrl("/login?error=Login+failed").defaultSuccessUrl("/user/user-profile")
					.and().logout().logoutUrl("/user/logout").logoutSuccessUrl("/").deleteCookies("JSESSIONID")
					.and().csrf().disable();
		}
	}


	/**
	 * Define third entry point, /guest/**
	 */
	@Configuration
	@Order(2)
	public static class App3ConfigurationAdapter extends WebSecurityConfigurerAdapter {

		protected void configure(HttpSecurity http) throws Exception {
			http.antMatcher("/guest/**").authorizeRequests().anyRequest().permitAll();
		}
	}
}
