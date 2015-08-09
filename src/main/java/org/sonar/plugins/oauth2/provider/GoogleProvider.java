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
import org.sonar.api.config.Settings;
import org.sonar.plugins.oauth2.OAuth2PluginException;

public class GoogleProvider extends GenericProvider {

  public GoogleProvider() {
    super(OAuthProviderType.GOOGLE);
  }

  @Override
  public OAuthClientRequest.AuthenticationRequestBuilder createRedirectRequestBuilder(Settings settings) {
    OAuthClientRequest.AuthenticationRequestBuilder redirectRequestBuilder;
    redirectRequestBuilder = super.createRedirectRequestBuilder(settings);
    redirectRequestBuilder.setParameter("response_type", "code");
    return redirectRequestBuilder;
  }

}
