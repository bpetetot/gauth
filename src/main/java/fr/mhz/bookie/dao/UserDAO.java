package fr.mhz.bookie.dao;

import com.googlecode.objectify.Key;
import fr.mhz.bookie.model.User;

import static fr.mhz.bookie.OfyService.ofy;

public class UserDAO {

    public User findById(String id) {
        return ofy().load().type(User.class).id(id).now();
    }

    /**
     * Updates an existing user or adds a new user.
     *
     * @param user the user to add or update.
     * @returns the user ID of the updated user.
     */
    public Long updateUser(User user) {
        System.out.println("Update user");
        Key<User> result = ofy().save().entity(user).now();
        user.setUserId(result.getId());
        return user.getUserId();
    }

    /**
     * Deletes a user from the datastore.
     *
     * @param userId the user ID of the user to delete.
     */
    public void deleteUser(Long userId) {
        User user = loadUser(userId);
        ofy().delete().entity(user);
    }

    /**
     * Loads a copy of a user from the datastore.
     *
     * @param userId the user ID of the user to load.
     * @returns a copy of the specified user if it exists or null if the user does not exist.
     */
    public User loadUser(Long userId) {
        return ofy().load().type(User.class).id(userId).now();
    }

    /**
     * Loads a copy of a user from the datastore.
     *
     * @param googleId the Google ID of the user to load.
     * @returns a copy of the specified user if it exists or null if the user does not exist.
     */
    public User loadUserWithGoogleId(String googleId) {
        return ofy().load().type(User.class).filter("googleId", googleId).first().now();
    }

    /**
     * Loads a copy of a user from the datastore with a session id.
     *
     * @param sessionId the Session ID of the user to load.
     * @returns a copy of the specified user if it exists or null if the user does not exist.
     */
    public User loadUserWithSessionId(String sessionId) {
        return ofy().load().type(User.class).filter("sessionId", sessionId).first().now();
    }

}
