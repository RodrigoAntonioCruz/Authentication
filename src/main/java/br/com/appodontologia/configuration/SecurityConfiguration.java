package br.com.appodontologia.configuration;

import br.com.appodontologia.repository.UserRepository;
import br.com.appodontologia.security.JwtAuthenticationFilter;
import br.com.appodontologia.security.JwtAuthenticationProvider;
import br.com.appodontologia.security.JwtTokenProvider;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

@Slf4j
@Configuration
@EnableWebSecurity
@AllArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration {
    private final Environment environment;
    private final EnvironmentConfiguration env;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    private static final String[] PUBLIC_MATCHERS = {
            "/v2/api-docs/**",
            "/swagger-ui/**",
            "/swagger-resources/**",
            "/swagger-ui.html",
            "/webjars/**"
    };

    private static final String[] PUBLIC_MATCHERS_GET = {

    };

    private static final String[] PUBLIC_MATCHERS_POST = {
            "/users/**"
    };

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository users) {
        return jwtAuthenticationProvider.userDetailsService(users);
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder encoder) {
        return jwtAuthenticationProvider.authenticationManager(userDetailsService, encoder);
    }

    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(env.getAllowedEndpoints());
        config.setAllowedHeaders(List.of("*"));
        config.setAllowedMethods(List.of("POST", "GET", "PATCH", "PUT", "DELETE", "OPTIONS", "HEAD"));
        config.setMaxAge(3600L);
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Bean
    protected SecurityFilterChain configure(HttpSecurity http, JwtTokenProvider token) throws Exception {

        if (Arrays.asList(environment.getActiveProfiles()).contains("dev")) {
            http.headers().frameOptions().disable();
        }

        return http.csrf().disable()
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(c -> c.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .authorizeRequests(authorize -> authorize
                        .antMatchers(PUBLIC_MATCHERS).permitAll()
                        .antMatchers(HttpMethod.GET, PUBLIC_MATCHERS_GET).permitAll()
                        .antMatchers(HttpMethod.POST, PUBLIC_MATCHERS_POST).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new JwtAuthenticationFilter(token), UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}