package fr.mhz.bookie.model;

import com.google.gson.annotations.Expose;
import com.googlecode.objectify.annotation.Cache;
import com.googlecode.objectify.annotation.Entity;
import com.googlecode.objectify.annotation.Id;
import com.googlecode.objectify.annotation.Index;
import fr.mhz.bookie.utils.Jsonifiable;

import java.util.Date;

/**
 * User representation
 */
@Entity
@Cache
public class User extends Jsonifiable {

    /**
     * Primary identifier of this User. Specific to Haiku+.
     */
    @Id
    public Long id;

    /**
     * Google ID for this User.
     */
    @Index
    public String googleId;

    /**
     * Associated session id
     */
    @Index
    public String sessionId;

    /**
     * Display name that this User .
     */
    @Expose
    public String displayName;

    /**
     * Public profile photo URL for this User.
     */
    @Expose
    public String photoUrl;

    /**
     * Email for this User.
     */
    @Expose
    public String email;

    /**
     * Access token for authentication
     */
    public String accessToken;

    /**
     * Refresh token for authentication
     */
    public String refreshToken;

    /**
     * Used to determine whether the User's cached data is "fresh" (less than one day old).
     */
    public Date lastUpdated = null;

    /**
     * 1 day in milliseconds for cached data calculations (1000 * 60 * 60 * 24).
     * TODO This is not a recommended way to manage time comparisons.
     */
    private static final Long ONE_DAY_IN_MS = 86400000L;

    public User() {
    }

    /**
     * Returns true if the cached user data is less than one day old
     */
    public boolean isDataFresh() {
        if (lastUpdated == null) {
            return false;
        }
        Date now = new Date();
        long timeDifference = now.getTime() - lastUpdated.getTime();
        return timeDifference < ONE_DAY_IN_MS;
    }

    public void setUserId(Long userId) {
        id = userId;
    }

    public void setGoogleUserId(String googleId) {
        this.googleId = googleId;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public void setPhotoUrl(String photoUrl) {
        this.photoUrl = photoUrl;
    }

    public void setLastUpdated() {
        lastUpdated = new Date();
    }

    public Long getUserId() {
        return id;
    }

    public String getGoogleUserId() {
        return googleId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getPhotoUrl() {
        return photoUrl;
    }

    public Date getLastUpdated() {
        return lastUpdated;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "User{" +
                "id='" + id + '\'' +
                ", googlePlusId='" + googleId + '\'' +
                ", sessionId=" + sessionId +
                ", displayName=" + displayName +
                '}';
    }
}
