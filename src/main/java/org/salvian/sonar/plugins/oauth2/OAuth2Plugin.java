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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.salvian.sonar.plugins.oauth2.provider.GoogleProvider;
import org.sonar.api.*;
import org.sonar.api.config.Settings;

import java.util.List;

/**
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 * @author <a href="https://github.com/alexlew">Alexandre Lewandowski</a>
 */
@Properties(value = {
        @Property(key = OAuth2Client.PROPERTY_SONAR_URL, name = "Sonar Server Base URL"),
        @Property(key = OAuth2Client.PROPERTY_PROVIDER, name = "OAuth2 Provider Name "
                + "(possible values are: FACEBOOK, FOURSQUARE, GITHUB, GOOGLE, INSTAGRAM, "
                + "LINKEDIN, MICROSOFT, PAYPAL, REDDIT, SALESFORCE, YAMMER)"),
        @Property(key = OAuth2Client.PROPERTY_CLIENT_ID, name = "OAuth2 Client ID"),
        @Property(key = OAuth2Client.PROPERTY_SECRET, name = "OAuth2 Client Secret"),
        @Property(key = GoogleProvider.PROPERTY_GOOGLE_HD, name = "Google OAUTH2 'hd' parameter")
})
public class OAuth2Plugin extends SonarPlugin {

    public List getExtensions() {
        return ImmutableList.of(Extensions.class);
    }

    public static final class Extensions extends ExtensionProvider implements ServerExtension {
        private final Settings settings;

        public Extensions(Settings settings) {
            this.settings = settings;
        }

        @Override
        public Object provide() {
            List<Class> extensions = Lists.newArrayList();
            if (isRealmEnabled()) {
                Preconditions.checkState(settings.getBoolean("sonar.authenticator.createUsers"), "Property sonar.authenticator.createUsers must be set to true.");
                extensions.add(OAuth2SecurityRealm.class);
                extensions.add(LoginPageRedirectFilter.class);
                extensions.add(OAuth2AuthenticationFilter.class);
                extensions.add(OAuth2ValidationFilter.class);
                extensions.add(OAuth2Authenticator.class);
                extensions.add(OAuth2Client.class);
                extensions.add(OAuth2UserProvider.class);
            }
            return extensions;
        }

        private boolean isRealmEnabled() {
            return OAuth2SecurityRealm.KEY.equalsIgnoreCase(settings.getString("sonar.security.realm"));
        }

    }
}
