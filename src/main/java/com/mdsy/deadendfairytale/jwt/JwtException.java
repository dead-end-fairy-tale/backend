package com.mdsy.deadendfairytale.jwt;

public class JwtException extends RuntimeException {
    
    public JwtException(String message) {
        super(message);
    }
    
    public JwtException(String message, Throwable cause) {
        super(message, cause);
    }
    
    public static class InvalidTokenException extends JwtException {
        public InvalidTokenException(String message) {
            super(message);
        }
    }
    
    public static class ExpiredTokenException extends JwtException {
        public ExpiredTokenException(String message) {
            super(message);
        }
    }
    
    public static class UnsupportedTokenException extends JwtException {
        public UnsupportedTokenException(String message) {
            super(message);
        }
    }
    
    public static class MalformedTokenException extends JwtException {
        public MalformedTokenException(String message) {
            super(message);
        }
    }
}
