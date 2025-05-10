package com.socialMind.auth.exception;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {
    
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Object> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
    
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<Object> handleBusinessException(BusinessException ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
    
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Object> handleBadCredentialsException(BadCredentialsException ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.UNAUTHORIZED, "Credenciais inválidas", ex);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
    
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, 
                                                                 HttpHeaders headers, 
                                                                 HttpStatus status, 
                                                                 WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        apiError.setMessage("Erro de validação");
        
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            apiError.addError(error.getField() + ": " + error.getDefaultMessage());
        }
        
        for (ObjectError error : ex.getBindingResult().getGlobalErrors()) {
            apiError.addError(error.getObjectName() + ": " + error.getDefaultMessage());
        }
        
        return new ResponseEntity<>(apiError, headers, apiError.getStatus());
    }
    
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Object> handleConstraintViolation(ConstraintViolationException ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        apiError.setMessage("Erro de validação");
        
        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            apiError.addError(violation.getRootBeanClass().getName() + " " + 
                    violation.getPropertyPath() + ": " + violation.getMessage());
        }
        
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleAll(Exception ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, "Erro interno do servidor", ex);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
}
