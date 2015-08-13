/*
 * Copyright 2015, Joseph "Deven" Phillips
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
import org.apache.oltu.oauth2.common.OAuthProviderType;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.sonar.api.config.Settings;
import org.sonar.api.ServerExtension;
import org.sonar.plugins.oauth2.provider.OAuth2Provider;
import org.sonar.plugins.oauth2.provider.Providers;

/**
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 * @author <a href="https://github.com/alexlew">Alexandre Lewandowski</a>
 */
public class OAuth2Client implements ServerExtension {
    
  public static final String PROPERTY_SONAR_URL = "sonar.oauth2.sonarServerUrl";
  public static final String PROPERTY_PROVIDER = "sonar.oauth2.provider";
  public static final String PROPERTY_CLIENT_ID = "sonar.oauth2.clientid";
  public static final String PROPERTY_SECRET = "sonar.oauth2.secret";
  public static final String PROPERTY_CALLBACK_URI = "oauth2/callback";

  Settings settings = null;

  /**
   * Default constructor. Accepts Sonar {@link Settings} in order to bootstrap
   * the class.
   * @param settings The {@link Settings} from the currently running Sonar instance.
   */
  public OAuth2Client(Settings settings) {
    this.settings = settings;
  }
  
  /**
   * Create an instance of {@link OAuthClientRequest} which uses the {@link Settings}
   * from Sonar to determine the auth location, redirect URL, and client ID.
   *
   * @return An instance of {@link OAuthClientRequest} ready to be used to send messages.
   * @throws OAuthSystemException If there is insufficient or conflicting configurations.
   * @param providerName name of the provider to use.
   */
  public OAuthClientRequest getRedirectRequest(String providerName) throws OAuth2PluginException {
    String name = "";
    try {
      name = sanitizeProviderName(providerName);
      OAuth2Provider provider = Providers.valueOf(name).get();
      return provider.createRedirectRequestBuilder(this.settings).buildQueryMessage();
    } catch (IllegalArgumentException e) {
      throw new OAuth2PluginException("Provider '" + name + "' is not supported");
    } catch (OAuthSystemException e) {
      throw new OAuth2PluginException("Cannot build redirect request.", e);
    }
  }

 public OAuthClientRequest getTokenRequest(String providerName, String code) throws OAuth2PluginException {
   String name = "";
   try {
     if(code == null || code.trim().equals("")) {
       throw new OAuth2PluginException("code is required");
     }
     name = sanitizeProviderName(providerName);
     OAuth2Provider provider = Providers.valueOf(name).get();
     return provider.createTokenRequestBuilder(this.settings, code).buildQueryMessage();
   } catch (IllegalArgumentException e) {
     throw new OAuth2PluginException("Provider '" + name + "' is not supported");
   } catch (OAuthSystemException e) {
     throw new OAuth2PluginException("Cannot build redirect request.", e);
   }
 }

  private String sanitizeProviderName(String providerName) throws OAuth2PluginException {
    if(providerName == null) {
      throw new OAuth2PluginException("Provider 'NULL' is not supported");
    }
    return providerName.toUpperCase().trim();
  }
}