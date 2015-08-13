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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.Settings;
import org.sonar.plugins.oauth2.OAuth2Client;

import static org.fest.assertions.Assertions.*;

public class GenericProviderTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void should_wrap_default_provider_configuration() {
    OAuth2Provider provider = new GenericProvider(OAuthProviderType.GITHUB);
    assertThat(provider.getAuthzEndpoint()).isEqualTo(OAuthProviderType.GITHUB.getAuthzEndpoint());
    assertThat(provider.getProviderName()).isEqualTo(OAuthProviderType.GITHUB.getProviderName());
    assertThat(provider.getTokenEndpoint()).isEqualTo(OAuthProviderType.GITHUB.getTokenEndpoint());
  }

  @Test
  public void buildRedirectRequest_given_a_provider_and_valid_Settings() throws Exception {
    OAuth2Provider provider = new GenericProvider(OAuthProviderType.GITHUB);
    Settings settings = new Settings()
                          .setProperty(OAuth2Client.PROPERTY_PROVIDER, "github")
                          .setProperty(OAuth2Client.PROPERTY_CLIENT_ID, "myClientId")
                          .setProperty(OAuth2Client.PROPERTY_SONAR_URL, "http://sonar:9111/web-context");

    OAuthClientRequest request = provider.createRedirectRequestBuilder(settings).buildQueryMessage();
    assertThat(request.getLocationUri()).startsWith(OAuthProviderType.GITHUB.getAuthzEndpoint());
    assertThat(request.getLocationUri()).contains("client_id=myClientId");
    assertThat(request.getLocationUri()).contains("redirect_uri=http%3A%2F%2Fsonar%3A9111%2Fweb-context%2Foauth2%2Fcallback");
    assertThat(request.getLocationUri()).contains("scope=email");
  }

  @Test
  public void buildTokenRequest_given_a_provider_and_valid_Settings() throws Exception {
    OAuth2Provider provider = new GenericProvider(OAuthProviderType.GITHUB);
    Settings settings = new Settings()
            .setProperty(OAuth2Client.PROPERTY_PROVIDER, "github")
            .setProperty(OAuth2Client.PROPERTY_CLIENT_ID, "myClientId")
            .setProperty(OAuth2Client.PROPERTY_SONAR_URL, "http://sonar:9111/web-context");

    OAuthClientRequest request = provider.createTokenRequestBuilder(settings).buildQueryMessage();
    assertThat(request.getLocationUri()).startsWith(OAuthProviderType.GITHUB.getTokenEndpoint());
    assertThat(request.getLocationUri()).contains("grant_type=password");
  }


}
