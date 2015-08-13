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
package org.sonar.plugins.oauth2.provider;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.OAuthProviderType;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.sonar.api.config.Settings;
import org.sonar.plugins.oauth2.OAuth2Client;

public class GenericProvider implements OAuth2Provider {

  private OAuthProviderType provider;

  public GenericProvider(OAuthProviderType provider) {
    this.provider = provider;
  }

  @Override
  public String getAuthzEndpoint() {
    return this.provider.getAuthzEndpoint();
  }

  @Override
  public String getProviderName() {
    return this.provider.getProviderName();
  }

  @Override
  public String getTokenEndpoint() {
    return this.provider.getTokenEndpoint();
  }

  @Override
  public OAuthClientRequest.AuthenticationRequestBuilder createRedirectRequestBuilder(Settings settings) {
    final String baseUrl = settings.getString(OAuth2Client.PROPERTY_SONAR_URL);
    final String callback = baseUrl + (baseUrl.endsWith("/") ? "" : "/") + OAuth2Client.PROPERTY_CALLBACK_URI;
    return OAuthClientRequest.authorizationLocation(getAuthzEndpoint())
            .setClientId(settings.getString(OAuth2Client.PROPERTY_CLIENT_ID))
            .setRedirectURI(callback)
            .setParameter("scope", "email");
  }

  @Override
  public OAuthClientRequest.TokenRequestBuilder createTokenRequestBuilder(Settings settings) {
    return OAuthClientRequest.tokenLocation(getTokenEndpoint())
            .setGrantType(GrantType.PASSWORD);
  }
}
