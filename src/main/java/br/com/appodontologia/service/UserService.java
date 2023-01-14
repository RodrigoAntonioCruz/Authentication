package br.com.appodontologia.service;

import br.com.appodontologia.domain.dto.users.request.SigninRequest;
import br.com.appodontologia.domain.dto.users.request.SignupRequest;
import br.com.appodontologia.domain.dto.users.response.JwtResponse;
import br.com.appodontologia.domain.dto.users.response.UserResponse;
import br.com.appodontologia.domain.entity.Users;
import br.com.appodontologia.repository.UserRepository;
import br.com.appodontologia.security.JwtAuthenticationProvider;
import br.com.appodontologia.security.JwtTokenProvider;
import br.com.appodontologia.util.Constants;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Slf4j
@Service
@AllArgsConstructor
public class UserService {
    private final ModelMapper mapper;
    private final PasswordEncoder pwd;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    public UserResponse create(SignupRequest request) {
        log.info(Constants.LOG_KEY_MESSAGE + Constants.LOG_KEY_METHOD , Constants.LOG_MSG_START_REGISTER_USER, Constants.LOG_METHOD_REGISTER);

        Users user = mapper.map(request, Users.class);
        user.setPassword(pwd.encode(request.getPassword()));

        return mapper.map(userRepository.save(user), UserResponse.class);
    }

    public JwtResponse authenticate(SigninRequest request) {
        log.info(Constants.LOG_KEY_MESSAGE + Constants.LOG_KEY_METHOD , Constants.LOG_MSG_START_AUTHENTICATE_USER, Constants.LOG_METHOD_AUTHENTICATE);

        var authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        return JwtResponse
                .builder()
                .token(jwtTokenProvider.generateToken(authentication))
                .build();
    }

    public JwtResponse refreshToken(HttpServletRequest request) {
        var authentication = jwtTokenProvider.getAuthentication(jwtTokenProvider.resolveToken(request));

        return JwtResponse
                .builder()
                .token(jwtTokenProvider.generateToken(authentication))
                .build();
    }
}
