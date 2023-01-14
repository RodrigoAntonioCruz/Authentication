package br.com.appodontologia.controller;

import br.com.appodontologia.configuration.SwaggerConfiguration;
import br.com.appodontologia.domain.dto.users.request.SigninRequest;
import br.com.appodontologia.domain.dto.users.request.SignupRequest;
import br.com.appodontologia.domain.dto.users.response.JwtResponse;
import br.com.appodontologia.service.UserService;
import br.com.appodontologia.util.Constants;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@Slf4j
@RestController
@AllArgsConstructor
@RequestMapping("/users")
@Api(tags = {SwaggerConfiguration.USER_TAG})
public class UserController {
    private final UserService userService;

    @PostMapping("/signup")
    @ApiResponses(value = {
            @ApiResponse(code = Constants.STATUS_CODE_CREATED, message = Constants.API_RESPONSE_CREATED),
            @ApiResponse(code = Constants.STATUS_CODE_BAD_REQUEST, message = Constants.API_RESPONSE_BAD_REQUEST),
            @ApiResponse(code = Constants.STATUS_CODE_UNAUTHORIZED, message = Constants.API_RESPONSE_UNAUTHORIZED),
            @ApiResponse(code = Constants.STATUS_CODE_INTERNAL_ERROR_SERVER, message = Constants.API_RESPONSE_INTERNAL_ERROR_SERVER)
    })
    @ApiOperation(value = "Realiza a criação de um novo usuário")
    public ResponseEntity<?> create(@Valid @RequestBody SignupRequest signUpRequest) {
        return ResponseEntity.created(ServletUriComponentsBuilder.fromCurrentRequest()
                .buildAndExpand(signUpRequest).toUri()).body(userService.create(signUpRequest));
    }

    @PostMapping("/signin")
    @ApiResponses(value = {
            @ApiResponse(code = Constants.STATUS_CODE_OK, message = Constants.API_RESPONSE_OK),
            @ApiResponse(code = Constants.STATUS_CODE_BAD_REQUEST, message = Constants.API_RESPONSE_BAD_REQUEST),
            @ApiResponse(code = Constants.STATUS_CODE_UNAUTHORIZED, message = Constants.API_RESPONSE_UNAUTHORIZED),
            @ApiResponse(code = Constants.STATUS_CODE_INTERNAL_ERROR_SERVER, message = Constants.API_RESPONSE_INTERNAL_ERROR_SERVER)
    })
    @ApiOperation(value = "Realiza a autenticação de um usuário existente")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody SigninRequest signinRequest) {
        return ResponseEntity.ok(userService.authenticate(signinRequest));
    }

    @PostMapping("/refresh_token")
    @ApiResponses(value = {
            @ApiResponse(code = Constants.STATUS_CODE_OK, message = Constants.API_RESPONSE_OK),
            @ApiResponse(code = Constants.STATUS_CODE_BAD_REQUEST, message = Constants.API_RESPONSE_BAD_REQUEST),
            @ApiResponse(code = Constants.STATUS_CODE_UNAUTHORIZED, message = Constants.API_RESPONSE_UNAUTHORIZED),
            @ApiResponse(code = Constants.STATUS_CODE_INTERNAL_ERROR_SERVER, message = Constants.API_RESPONSE_INTERNAL_ERROR_SERVER)
    })
    @ApiOperation(value = "Realiza a geração de um novo token JWT")
    public JwtResponse refreshToken(HttpServletRequest request) {
        return userService.refreshToken(request);
    }

    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    @GetMapping("/test/{id}")
    public String test(@PathVariable("id") String id) {
        return "Olá mundo!" + id;
    }

    @GetMapping("/test")
    public String test() { return "Olá mundo cruel!"; }
}
