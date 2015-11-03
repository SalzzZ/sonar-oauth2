package org.salvian.sonar.plugins.oauth2;

import org.sonar.api.web.ServletFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by salvian on 03/11/15.
 */
public class LoginPageRedirectFilter extends ServletFilter {
    @Override
    public ServletFilter.UrlPattern doGetPattern() {
        return ServletFilter.UrlPattern.create("/sessions/new");
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        ((HttpServletResponse) response).sendRedirect("/oauth2");
    }

    @Override
    public void destroy() {

    }
}
