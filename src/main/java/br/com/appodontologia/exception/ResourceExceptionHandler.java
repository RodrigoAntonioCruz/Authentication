package br.com.appodontologia.exception;

import br.com.appodontologia.util.Constants;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static br.com.appodontologia.util.Constants.X_TRACEID;

@Slf4j
@ControllerAdvice
public class ResourceExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Object> validation(AuthenticationException e, HttpServletRequest request) {
        return getException(HttpStatus.UNAUTHORIZED, Constants.ERROR_UNAUTHORIZED, e.getMessage(), request.getRequestURI(), List.of());
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Object> validation(UsernameNotFoundException e, HttpServletRequest request) {
        return getException(HttpStatus.UNAUTHORIZED, Constants.ERROR_UNAUTHORIZED, e.getMessage(), request.getRequestURI(), List.of());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> validation(AccessDeniedException e, HttpServletRequest request) {
        return getException(HttpStatus.FORBIDDEN, Constants.ERROR_FORBIDDEN, Constants.MESSAGE_FORBIDDEN, request.getRequestURI(), List.of());
    }
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Object> validation(MethodArgumentNotValidException e, HttpServletRequest request) {
        return getException(HttpStatus.UNPROCESSABLE_ENTITY, Constants.ERROR_VALIDATION, Constants.MESSAGE_VERIFY_REQUEST_DATA, request.getRequestURI(), e.getBindingResult().getFieldErrors());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Object> validation(HttpMessageNotReadableException e, HttpServletRequest request) {
        return getException(HttpStatus.BAD_REQUEST, Constants.ERROR_VALIDATION, Constants.MESSAGE_VERIFY_REQUEST_DATA, request.getRequestURI(), List.of());
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<Object> validation(NoSuchElementException e, HttpServletRequest request) {
        return getException(HttpStatus.BAD_REQUEST, Constants.ERROR_VALIDATION, Constants.MESSAGE_VERIFY_REQUEST_DATA, request.getRequestURI(), List.of());
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<Object> validation(NullPointerException e, HttpServletRequest request) {
        return getException(HttpStatus.BAD_REQUEST, Constants.ERROR_VALIDATION, Constants.MESSAGE_VERIFY_REQUEST_DATA, request.getRequestURI(), List.of());
    }

    private ResponseEntity<Object> getException(HttpStatus httpStatus, String error, String message, String path, List<FieldError> errors) {
        BusinessException exception = BusinessException.builder().timestamp(System.currentTimeMillis()).httpStatus(httpStatus.value())
                .error(error).message(message).path(path).build();

        errors.forEach(e -> {
            exception.addError(e.getField(), e.getDefaultMessage());
        });

        var responseHeaders = new HttpHeaders();
        responseHeaders.set(X_TRACEID, String.valueOf(UUID.randomUUID()));

        return ResponseEntity.status(exception.getHttpStatus()).headers(responseHeaders).body(exception);
    }
}
