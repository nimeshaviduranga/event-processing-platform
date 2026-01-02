package com.eventprocessing.commonsecurity.security;

import lombok.Data;

import java.util.List;

public class SecurityContextHolder {

    private static final ThreadLocal<SecurityContext> CONTEXT = new ThreadLocal<>();

    public static void setContext(SecurityContext context) {
        CONTEXT.set(context);
    }

    public static SecurityContext getContext() {
        SecurityContext context = CONTEXT.get();
        if (context == null) {
            context = new SecurityContext();
            CONTEXT.set(context);
        }
        return context;
    }

    public static void clear() {
        CONTEXT.remove();
    }

    @Data
    public static class SecurityContext {
        private String userId;
        private String email;
        private String workspaceId;
        private List<String> roles;
        private boolean authenticated;

        public boolean hasRole(String role) {
            return roles != null && roles.contains(role);
        }

        public boolean hasAnyRole(String... roles) {
            if (this.roles == null) return false;
            for (String role : roles) {
                if (this.roles.contains(role)) {
                    return true;
                }
            }
            return false;
        }
    }
}