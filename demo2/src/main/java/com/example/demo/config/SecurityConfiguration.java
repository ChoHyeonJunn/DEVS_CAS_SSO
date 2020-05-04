package com.example.demo.config;

import java.util.Arrays;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private AuthenticationEntryPoint authenticationEntryPoint;
	@Autowired
	ServiceProperties serviceProperties;
	@Autowired
	private AuthenticationProvider authenticationProvider;
	@Autowired
	private SingleSignOutFilter singleSignOutFilter;
	@Autowired
	private LogoutFilter casLogoutFilter;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().regexMatchers("/secured.*", "/login").authenticated()//
				.and().authorizeRequests().antMatchers("/favicon.ico", "/static/**").permitAll()//
				.and().authorizeRequests().antMatchers("/admin/**").hasAuthority("ADMIN")//
				.and().authorizeRequests().antMatchers("/user/**").hasAuthority("USER")//
				.and().authorizeRequests().regexMatchers("/").permitAll()//
				.and().logout().logoutSuccessUrl("/logout/cas")//
				.and().httpBasic().authenticationEntryPoint(authenticationEntryPoint)

				// logout 은 csrf사용시 post로만 logout 가능 , 일단 test용으로 csrf 해제
				.and().csrf().disable()//
				.addFilterBefore(singleSignOutFilter, CasAuthenticationFilter.class)//
				.addFilterBefore(casLogoutFilter, LogoutFilter.class);
	}

	@Bean
	public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setServiceProperties(serviceProperties); // Bean 위치 : CasConfig.java
		filter.setAuthenticationManager(authenticationManager());
		return filter;
	}

	@Bean
	public AuthenticationManager authenticationManager() {
		return new ProviderManager(Arrays.asList(authenticationProvider));
	}
}
