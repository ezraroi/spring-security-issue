package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Created by rezra3 on 8/7/16.
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    protected void configureGlobal(AuthenticationManagerBuilder auth)  throws Exception {
        auth.inMemoryAuthentication().withUser("admin").password("admin").roles("ADMIN","user");
        auth.inMemoryAuthentication().withUser("user1").password("user1").roles("USER");
        auth.inMemoryAuthentication().withUser("user2").password("user2").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/manage/health","/manage/info").permitAll()
                .antMatchers("/manage/**", "/debug/**").hasRole("ADMIN")
                .and()
                .csrf().disable().logout().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .exceptionHandling();
    }


}
