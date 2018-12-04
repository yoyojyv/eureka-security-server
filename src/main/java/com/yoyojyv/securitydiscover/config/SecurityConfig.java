package com.yoyojyv.securitydiscover.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("discUser").password("{noop}discUser").roles("SYSTEM")
                .and()
                .withUser("admin").password("{noop}admin").roles("ADMIN")
                .and()
                .withUser("actuator").password("{noop}actuator").roles("ACTUATOR");
        ;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // http.csrf().ignoringAntMatchers("/eureka/**");

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).and()
                .httpBasic().and()/*disable().*/
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/lastn").hasRole("ADMIN")
                .antMatchers("/actuator/health**").permitAll()
                .requestMatchers(EndpointRequest.to("info")).permitAll()
                .requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("ACTUATOR")
                // .antMatchers("/actuator/**").hasRole("ACTUATOR")
                .antMatchers("/eureka/css/**","/eureka/images/**","/eureka/fonts/**", "/eureka/js/**").permitAll()
                .antMatchers("/eureka/**").hasRole("SYSTEM")
                .anyRequest().denyAll()
                .and().csrf().disable();
    }

}
