package br.com.appodontologia.security;

import br.com.appodontologia.exception.AuthenticationException;
import br.com.appodontologia.repository.UserRepository;
import br.com.appodontologia.util.Constants;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
@Slf4j
@Component
@AllArgsConstructor
public class JwtAuthenticationProvider {
    public UserDetailsService userDetailsService(UserRepository users) {
        return (email) -> users.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(Constants.FIELD_USER_NOT_FOUND + email + Constants.MESSAGE_NOT_FOUND));
    }

    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder encoder) {
        return authentication -> {
            String username = String.valueOf(authentication.getPrincipal());
            String password = String.valueOf(authentication.getCredentials());

            UserDetails user = userDetailsService.loadUserByUsername(username);

            if (!encoder.matches(password, user.getPassword())) {
                throw new AuthenticationException(Constants.MESSAGE_INCORRECT_PASSWORD);
            }

            if (!user.isEnabled()) {
                throw new AuthenticationException(Constants.MESSAGE_DESABLED_ACCOUNT);
            }

            return new UsernamePasswordAuthenticationToken(username, null, user.getAuthorities());
        };
    }
}
