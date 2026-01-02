package com.eventprocessing.commonsecurity.security;

import com.eventprocessing.common.util.Constants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                String userId = tokenProvider.getUserIdFromToken(jwt);
                String email = tokenProvider.getEmailFromToken(jwt);
                String workspaceId = tokenProvider.getWorkspaceIdFromToken(jwt);
                List<String> roles = tokenProvider.getRolesFromToken(jwt);

                // Set Spring Security context
                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Set custom security context
                com.eventprocessing.common.security.SecurityContextHolder.SecurityContext ctx =
                        new com.eventprocessing.common.security.SecurityContextHolder.SecurityContext();
                ctx.setUserId(userId);
                ctx.setEmail(email);
                ctx.setWorkspaceId(workspaceId);
                ctx.setRoles(roles);
                ctx.setAuthenticated(true);

                com.eventprocessing.common.security.SecurityContextHolder.setContext(ctx);
            }
        } catch (Exception ex) {
            log.error("Could not set user authentication in security context", ex);
        }

        filterChain.doFilter(request, response);

        // Clear context after request
        com.eventprocessing.common.security.SecurityContextHolder.clear();
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(Constants.HEADER_AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
