package com.eventprocessing.commonsecurity.security;

import com.eventprocessing.common.util.Constants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String apiKey = getApiKeyFromRequest(request);
            String workspaceId = request.getHeader(Constants.HEADER_WORKSPACE_ID);

            if (StringUtils.hasText(apiKey) && StringUtils.hasText(workspaceId)) {
                // Note: Actual validation should be done by calling user-management service
                // For now, we just set the context
                com.eventprocessing.common.security.SecurityContextHolder.SecurityContext ctx =
                        new com.eventprocessing.common.security.SecurityContextHolder.SecurityContext();
                ctx.setWorkspaceId(workspaceId);
                ctx.setAuthenticated(true);

                com.eventprocessing.common.security.SecurityContextHolder.setContext(ctx);

                log.debug("API Key authentication successful for workspace: {}", workspaceId);
            }
        } catch (Exception ex) {
            log.error("Could not set API key authentication in security context", ex);
        }

        filterChain.doFilter(request, response);

        // Clear context after request
        com.eventprocessing.common.security.SecurityContextHolder.clear();
    }

    private String getApiKeyFromRequest(HttpServletRequest request) {
        return request.getHeader(Constants.HEADER_API_KEY);
    }
}