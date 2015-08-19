/*
 * Copyright 2015, Alexandre Lewandowski
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

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.sonar.api.security.UserDetails;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.mockito.Mockito.*;

public class OAuth2ValidationFilterTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Mock private OAuth2Client client;
  @Mock private HttpServletRequest request;
  @Mock private HttpServletResponse response;
  @Mock private HttpSession session;
  @Mock private FilterChain chain;


  @Before
  public void initMock(){
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void filter_should_redirect_if_something_wrong_append() throws Exception {
    OAuth2ValidationFilter filter = new OAuth2ValidationFilter(client);
    when(request.getSession()).thenThrow(new NullPointerException());

    filter.doFilter(request, response, chain);

    verify(response).sendRedirect(OAuth2ValidationFilter.UNAUTHORIZED_URI);
  }

  @Test
  public void filter_should_add_user_in_request_parameter() throws Exception {
    OAuth2ValidationFilter filter = new OAuth2ValidationFilter(client);
    when(request.getSession()).thenThrow(new NullPointerException());
    when(request.getSession(true)).thenReturn(session);

    filter.doFilter(request, response, chain);

    verify(response).sendRedirect(OAuth2ValidationFilter.UNAUTHORIZED_URI);
    verify(request).setAttribute(eq(OAuth2AuthenticationFilter.USER_ATTRIBUTE), any(UserDetails.class));
    verify(chain).doFilter(request, response);
  }

}
