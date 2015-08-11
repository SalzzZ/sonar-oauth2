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

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.Settings;

import static org.fest.assertions.Assertions.*;

public class OAuth2ClientTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void getRedirectRequest_given_a_valid_provider() throws Exception {
    Settings settings = new Settings()
                          .setProperty(OAuth2Client.PROPERTY_SONAR_URL, "https://myserver:9000/sonar");
    OAuth2Client client = new OAuth2Client(settings);

    OAuthClientRequest request = client.getRedirectRequest("google");
    assertThat(request.getLocationUri()).startsWith("https://accounts.google.com/o/oauth2/auth");

    request = client.getRedirectRequest("github");
    assertThat(request.getLocationUri()).startsWith("https://github.com/login/oauth/authorize");
  }

  @Test
  public void client_does_not_support_unknow_provider() throws Exception {
    thrown.expect(OAuth2PluginException.class);
    thrown.expectMessage("Provider 'UNKNOWN' is not supported");
    Settings settings = new Settings()
            .setProperty(OAuth2Client.PROPERTY_SONAR_URL, "https://myserver:9000/sonar");
    OAuth2Client client = new OAuth2Client(settings);

    client.getRedirectRequest("unknown");
  }

  @Test
  public void client_does_not_support_null_provider() throws Exception {
    thrown.expect(OAuth2PluginException.class);
    thrown.expectMessage("Provider 'NULL' is not supported");
    Settings settings = new Settings()
            .setProperty(OAuth2Client.PROPERTY_SONAR_URL, "https://myserver:9000/sonar");
    OAuth2Client client = new OAuth2Client(settings);

    client.getRedirectRequest(null);
  }

  @Test
  public void client_does_not_support_empty_provider() throws Exception {
    thrown.expect(OAuth2PluginException.class);
    thrown.expectMessage("Provider '' is not supported");
    Settings settings = new Settings()
            .setProperty(OAuth2Client.PROPERTY_SONAR_URL, "https://myserver:9000/sonar");
    OAuth2Client client = new OAuth2Client(settings);

    client.getRedirectRequest("  ");
  }

}
