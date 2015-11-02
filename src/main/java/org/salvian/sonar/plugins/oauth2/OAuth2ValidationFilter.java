/*
 * Copyright 2015, Joseph "Deven" Phillips
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.salvian.sonar.plugins.oauth2;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.UserDetails;
import org.sonar.api.web.ServletFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * @author <a href="">Deven Phillips</a>
 */
public class OAuth2ValidationFilter extends ServletFilter {
    private final static Logger LOG = LoggerFactory.getLogger(OAuth2ValidationFilter.class);
    public final static String OAUTH2_TOKEN_SESSION_KEY = "sonar.oauth2.token";
    private static final String UNAUTHORIZED_URI = "/oauth2/unauthorized";

    final private OAuth2Client client;

    public OAuth2ValidationFilter(OAuth2Client client) {
        this.client = client;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public UrlPattern doGetPattern() {
        return UrlPattern.create(OAuth2Client.PROPERTY_CALLBACK_URI);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            LOG.info("Enter Validation Filter.");
            OAuthAuthzResponse oar = OAuthAuthzResponse.oauthCodeAuthzResponse(httpRequest);
            String code = oar.getCode();
            OAuthClientRequest clientReq = client.getTokenRequest("GOOGLE", code);
            OAuthClient client = new OAuthClient(new URLConnectionClient());
            OAuthJSONAccessTokenResponse tokenResponse = client.accessToken(clientReq);
            HttpSession session = httpRequest.getSession(true);
            session.setAttribute(OAUTH2_TOKEN_SESSION_KEY, tokenResponse);
            LOG.info("Token {} expires in {}.", tokenResponse.getAccessToken(), tokenResponse.getExpiresIn());
            UserDetails user = this.client.getVerifiedUser("GOOGLE", tokenResponse);
            if (user != null)
                request.setAttribute(OAuth2AuthenticationFilter.USER_ATTRIBUTE, user);
            chain.doFilter(request, response);
        } catch (Exception e) {
            LOG.error("Cannot check identity.", e);
            ((HttpServletResponse) response).sendRedirect(UNAUTHORIZED_URI);
        }
    }

    @Override
    public void destroy() {
    }

}
