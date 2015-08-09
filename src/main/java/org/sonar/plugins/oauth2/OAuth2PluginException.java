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

public class OAuth2PluginException extends Exception {

  public OAuth2PluginException() {
    super();
  }

  public OAuth2PluginException(String message) {
    super(message);
  }

  public OAuth2PluginException(String message, Throwable cause) {
    super(message, cause);
  }

  public OAuth2PluginException(Throwable cause) {
    super(cause);
  }

}
