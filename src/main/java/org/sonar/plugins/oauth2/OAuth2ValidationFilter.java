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

import lombok.extern.slf4j.Slf4j;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.sonar.api.security.UserDetails;
import org.sonar.api.web.ServletFilter;

/**
 * @author <a href="">Deven Phillips</a>
 */
@Slf4j
public class OAuth2ValidationFilter extends ServletFilter {

  public final static String OAUTH2_CODE = "sonar.oauth2.code";
  protected static String UNAUTHORIZED_URI = "/sessions/login";

  final private OAuth2Client client;

  public OAuth2ValidationFilter(OAuth2Client client) {
    this.client = client;
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
  }

  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create("/oauth2/callback*");
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    try {
      LOG.info("Enter Validation Filter.");
      UserDetails user = (UserDetails) ((HttpServletRequest) request).getSession().getAttribute(OAuth2AuthenticationFilter.USER_ATTRIBUTE);
      String code = (String) ((HttpServletRequest) request).getSession().getAttribute(OAUTH2_CODE);
      OAuthClientRequest clientReq = client.getTokenClientRequest(user, code);
      OAuthClient client = new OAuthClient(new URLConnectionClient());
      OAuthJSONAccessTokenResponse tokenResponse = client.accessToken(clientReq);
      LOG.info("Token expires in {}.", tokenResponse.getExpiresIn());
      ((HttpServletRequest) request).getSession().setAttribute("tokenJson", tokenResponse);
      chain.doFilter(request, response);
    } catch (Exception e) {
      ((HttpServletResponse)response).sendRedirect(UNAUTHORIZED_URI);
    }
  }

  @Override
  public void destroy() {
  }

}
