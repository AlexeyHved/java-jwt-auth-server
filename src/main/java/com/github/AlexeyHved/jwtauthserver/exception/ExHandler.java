package com.github.AlexeyHved.jwtauthserver.exception;

import com.github.AlexeyHved.jwtauthserver.utils.Const;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestValueException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.ResourceAccessException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice
@Slf4j
public class ExHandler {


    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse constraintViolationHandler(final ConstraintViolationException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.BAD_REQUEST)
                .reason("Validation error")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();

        log.warn(errorResponse.toString());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse passInvalidExHandler(final PasswordValidationEx e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.BAD_REQUEST)
                .reason("Invalid pass")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();
        log.warn(e.getMessage());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponse notFoundExceptionHandler(final ResourceNotFoundException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.NOT_FOUND)
                .reason("Resource not found")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();

        log.warn(errorResponse.toString());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponse illegalArgumentExceptionHandler(final IllegalArgumentException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.NOT_FOUND)
                .reason("Illegal Argument")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();

        log.warn(errorResponse.toString());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.CONFLICT)
    public ErrorResponse dataIntegrityHandler(final DataIntegrityViolationException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.CONFLICT)
                .reason("Database error")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();

        log.warn(errorResponse.toString());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.CONFLICT)
    public ErrorResponse resAlreayExist(final ResourceAlreadyExistEx e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.CONFLICT)
                .reason("Already exist")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();

        log.warn(errorResponse.toString());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.CONFLICT)
    public ErrorResponse resourceAccessExceptionHandler(final ResourceAccessException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.CONFLICT)
                .reason("No Access")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();

        log.warn(errorResponse.toString());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse servletExceptionHAndler(final MissingRequestValueException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.BAD_REQUEST)
                .reason("MissingRequestValueException")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();
        log.warn(e.getMessage());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse methodArgumentNotValidHandler(final MethodArgumentNotValidException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.BAD_REQUEST)
                .reason("MethodArgumentNotValidException")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();
        log.warn(e.getMessage());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse jwtExceptionHandler(final JwtException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.UNAUTHORIZED)
                .reason("Jwt Exception")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();
        log.warn(e.getMessage());
        return errorResponse;
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorResponse handleThrowable(final Throwable e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .errors(e.getStackTrace())
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .reason("Oops, an unexpected error has occurred")
                .message(e.getMessage())
                .timestamp(LocalDateTime.now().format(Const.DTF))
                .build();

        log.warn(errorResponse.toString());
        return errorResponse;
    }
}
