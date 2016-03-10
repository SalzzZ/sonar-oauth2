package org.salvian.sonar.plugins.oauth2;

/**
 * Created by salvian on 30/10/15.
 */
public class GenericProfile {
    private String name;
    private String email;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
