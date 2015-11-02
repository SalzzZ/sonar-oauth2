package org.salvian.sonar.plugins.oauth2;

/**
 * Created by salvian on 30/10/15.
 */
public class GenericProfile {
    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    private String name;
    private String email;

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }
}
