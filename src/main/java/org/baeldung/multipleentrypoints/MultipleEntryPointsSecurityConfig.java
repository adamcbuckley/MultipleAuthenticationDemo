package org.baeldung.multipleentrypoints;

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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;

@Configuration
@EnableWebSecurity
public class MultipleEntryPointsSecurityConfig {

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
		final SAMLUserDetailsService manager = new SAMLUserDetailsService() {
			@Override
			public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
				final String userId = credential.getNameID().getValue();
				final String[] groups = credential.getAttributeAsStringArray("GROUPS");
				final List<GrantedAuthority> authorities = new ArrayList<>();
				for (final String group : groups) {
					authorities.add(new SimpleGrantedAuthority(group));
				}
				return new User(userId, "", authorities);
			}
		};

		return manager;
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
					.antMatchers("/admin/**").hasRole("ADMIN")
					.and().exceptionHandling().accessDeniedPage("/403");

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
					.and().formLogin().loginProcessingUrl("/user/login")
					.failureUrl("/userLogin?error=loginError").defaultSuccessUrl("/user/myUserPage")
					.and().logout().logoutUrl("/user/logout").logoutSuccessUrl("/multipleHttpLinks")
					.deleteCookies("JSESSIONID")
					.and().exceptionHandling()
					.defaultAuthenticationEntryPointFor(loginUrlauthenticationEntryPointWithWarning(), new AntPathRequestMatcher("/user/private/**"))
					.defaultAuthenticationEntryPointFor(loginUrlauthenticationEntryPoint(), new AntPathRequestMatcher("/user/general/**"))
					.accessDeniedPage("/403")
					.and().csrf().disable();
		}

		@Bean
		public AuthenticationEntryPoint loginUrlauthenticationEntryPoint() {
			return new LoginUrlAuthenticationEntryPoint("/userLogin");
		}

		@Bean
		public AuthenticationEntryPoint loginUrlauthenticationEntryPointWithWarning() {
			return new LoginUrlAuthenticationEntryPoint("/userLoginWithWarning");
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
