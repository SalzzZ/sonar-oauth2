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
package org.sonar.plugins.oauth2;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import lombok.extern.slf4j.Slf4j;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.sonar.api.web.ServletFilter;

/**
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 */
@Slf4j
public class OAuth2AuthenticationFilter extends ServletFilter {

  public static final String USER_ATTRIBUTE = "sonar.oauth.user";

  final private OAuth2Client client;

  public OAuth2AuthenticationFilter(OAuth2Client client) {
    this.client = client;
  }

  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create("/sessions/new");
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {

  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpSession session = ((HttpServletRequest) request).getSession(true);
    if (session.getAttribute(OAuth2ValidationFilter.OAUTH2_TOKEN_SESSION_KEY) == null) {   // TODO: Check session state for an existing OAuth code/refresh token
      try {
        OAuthClientRequest req = client.getRedirectRequest("google");
        ((HttpServletResponse) response).sendRedirect(req.getLocationUri());
      } catch (OAuth2PluginException ex) {
        LOG.error("Error creating OAuthClientRequest", ex);
      }
    } else {
      OAuthJSONAccessTokenResponse token
              = (OAuthJSONAccessTokenResponse) session.getAttribute(OAuth2ValidationFilter.OAUTH2_TOKEN_SESSION_KEY);
      if (session.getAttribute(USER_ATTRIBUTE) == null){
        //retrieve user
      }
      chain.doFilter(request, response);
    }
  }

  @Override
  public void destroy() {
  }

}
