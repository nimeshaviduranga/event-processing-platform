package com.eventprocessing.commonsecurity.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordUtil {

    private static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder(12);

    public static String hashPassword(String plainPassword) {
        return PASSWORD_ENCODER.encode(plainPassword);
    }

    public static boolean verifyPassword(String plainPassword, String hashedPassword) {
        return PASSWORD_ENCODER.matches(plainPassword, hashedPassword);
    }

    public static boolean isPasswordComplex(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }
}