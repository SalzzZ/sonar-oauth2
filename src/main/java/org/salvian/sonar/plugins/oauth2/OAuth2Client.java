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
package org.salvian.sonar.plugins.oauth2;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.salvian.sonar.plugins.oauth2.provider.OAuth2Provider;
import org.salvian.sonar.plugins.oauth2.provider.Providers;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;
import org.sonar.api.security.UserDetails;

/**
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 * @author <a href="https://github.com/alexlew">Alexandre Lewandowski</a>
 */
public class OAuth2Client implements ServerExtension {

    public static final String PROPERTY_SONAR_URL = "sonar.web.host";
    public static final String PROPERTY_PROVIDER = "sonar.auth.provider";
    public static final String PROPERTY_CLIENT_ID = "sonar.auth.clientId";
    public static final String PROPERTY_SECRET = "sonar.auth.secret";
    public static final String PROPERTY_CALLBACK_URI = "/oauth2/callback";

    private Settings settings = null;

    /**
     * Default constructor. Accepts Sonar {@link Settings} in order to bootstrap
     * the class.
     *
     * @param settings The {@link Settings} from the currently running Sonar instance.
     */
    public OAuth2Client(Settings settings) {
        this.settings = settings;
    }

    /**
     * Create an instance of {@link OAuthClientRequest} which uses the {@link Settings}
     * from Sonar to determine the auth location, redirect URL, and client ID.
     *
     * @param providerName name of the provider to use.
     * @return An instance of {@link OAuthClientRequest} ready to be used to send messages.
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
            if (code == null || "".equals(code.trim())) {
                throw new OAuth2PluginException("code is required");
            }
            name = sanitizeProviderName(providerName);
            OAuth2Provider provider = Providers.valueOf(name).get();
            return provider.createTokenRequestBuilder(this.settings, code).buildBodyMessage();
        } catch (IllegalArgumentException e) {
            throw new OAuth2PluginException("Provider '" + name + "' is not supported");
        } catch (OAuthSystemException e) {
            throw new OAuth2PluginException("Cannot build redirect request.", e);
        }
    }


    public UserDetails getVerifiedUser(String providerName, OAuthJSONAccessTokenResponse tokenResponse) throws OAuth2PluginException {
        String name = "";
        try {
            if (tokenResponse == null) {
                throw new OAuth2PluginException("token response is required");
            }
            name = sanitizeProviderName(providerName);
            OAuth2Provider provider = Providers.valueOf(name).get();
            GenericProfile profile = provider.validateTokenAndGetUser(settings, tokenResponse);
            if (profile != null) {
                UserDetails user = new UserDetails();
                user.setName(profile.getName());
                user.setEmail(profile.getEmail());
                return user;
            }
            return null;
        } catch (IllegalArgumentException e) {
            throw new OAuth2PluginException("Provider '" + name + "' is not supported");
        }
    }

    private String sanitizeProviderName(String providerName) throws OAuth2PluginException {
        if (providerName == null) {
            throw new OAuth2PluginException("Provider 'NULL' is not supported");
        }
        return providerName.toUpperCase().trim();
    }
}
