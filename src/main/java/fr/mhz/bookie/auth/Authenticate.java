
package fr.mhz.bookie.auth;

import com.google.api.client.auth.oauth2.*;
import com.google.api.client.googleapis.auth.oauth2.*;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.json.JsonFactory;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.model.Person;
import com.google.gson.JsonParseException;
import fr.mhz.bookie.auth.exeptions.CredentialNotFoundException;
import fr.mhz.bookie.model.User;
import fr.mhz.bookie.services.Services;
import fr.mhz.bookie.utils.Jsonifiable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Provides the logic for authenticating a user before continuing with the intended API call.
 */
public class Authenticate {

    /**
     * This is the default redirect URI for web applications and tells the browser to return
     * to the parent of the dialog. This value is used to validate a redirect URI provided in
     * the X-Oauth-Code header. It is important to validate all supplied redirect URIs, as
     * explained in the OAuth specification (http://tools.ietf.org/html/rfc6749#section-10.6).
     */
    private static final String WEB_REDIRECT_URI = "postmessage";

    /**
     * This is the default redirect URI for installed applications and is the equivalent of
     * a "null" value. This value is used to validate a redirect URI provided in
     * the X-Oauth-Code header. It is important to validate all supplied redirect URIs, as
     * explained in the OAuth specification (http://tools.ietf.org/html/rfc6749#section-10.6).
     */
    private static final String INSTALLED_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob";

    /**
     * Authentication identifier for an ID token.
     */
    private static final String BEARER_SCHEME = "Bearer";

    /**
     * Authentication identifier for an authorization code.
     */
    private static final String CODE_SCHEME = "X-OAuth-Code";

    /**
     * Name of the authorization code authorization header.
     */
    private static final String CODE_AUTHORIZATION_HEADER_NAME = CODE_SCHEME;

    /**
     * Regular expression for identifying an authorization code header.
     */
    private static final Pattern CODE_REGEX = Pattern.compile("\\s*(\\S+)(?:\\s+redirect_uri='(.+)')?");

    /**
     * Name of the Bearer authorization header.
     */
    private static final String BEARER_AUTHORIZATION_HEADER_NAME = "Authorization";

    /**
     * Regular expression for identifying an authorization ID token header.
     */
    private static final Pattern BEARER_REGEX = Pattern.compile("\\s*" + BEARER_SCHEME + "\\s+(\\S+)");

    /**
     * For use in verifying access tokens, as the client library currently does not provide
     * a validation method for access tokens.
     */
    private static final String TOKEN_INFO_ENDPOINT = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s";

    /**
     * Regular expression for identifying client IDs from the same API Console project.
     */
    private static final Pattern CLIENT_ID_REGEX = Pattern.compile("(^\\d+).*");

    /**
     * For use in building authentication response headers.
     */
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    /**
     * For use in building authentication response headers.
     */
    private static final String GOOGLE_REALM = "realm=\"https://www.google.com/accounts/AuthSubRequest\"";

    /**
     * Verifier object for use in validating ID tokens.
     */
    private final GoogleIdTokenVerifier idTokenVerifier;

    /**
     * Repository pattern to wrap a static/final call for testing purposes.
     */
    private final GoogleIdTokenRepository tokenRepo;

    /**
     * Logger for the Authenticate class.
     */
    Logger logger = Logger.getLogger("Authenticate");

    Authenticate(ExecutorService executor) {
        this(new GoogleIdTokenVerifier(Services.TRANSPORT, Services.JSON_FACTORY), new GoogleIdTokenRepository(), executor);
    }

    Authenticate(GoogleIdTokenVerifier verifier, GoogleIdTokenRepository repo, ExecutorService executor) {
        idTokenVerifier = verifier;
        tokenRepo = repo;
        Services.initClientSecretInfo();
    }

    /**
     * Authenticates a user by associating this session with a user based on a provided ID token
     * {@code idAuth} and by associating a user with valid credentials based on a provided
     * authorization code {@code codeAuth}. Once a request has been authenticated, calls
     * chain.doFilter() to invoke the associated servlet and complete the API call made by
     * the client.
     *
     * @return the User object indicating the authenticated and authorized user, or null
     * to indicate that additional authentication information is needed.
     */
    User requireAuthentication(String sessionId, HttpServletRequest request, HttpServletResponse response) {

        User user = null;
        String googleUserId = null;

        // Isolate the authorization piece of the relevant headers, if they exist.
        String codeAuth = parseAuthorizationHeader(request, CODE_AUTHORIZATION_HEADER_NAME, CODE_REGEX, 1);
        String idAuth = parseAuthorizationHeader(request, BEARER_AUTHORIZATION_HEADER_NAME, BEARER_REGEX, 1);
        String redirectUri = parseAuthorizationHeader(request, CODE_AUTHORIZATION_HEADER_NAME, CODE_REGEX, 2);

        // Must be one of these two values, correct to INSTALLED otherwise.
        if (!WEB_REDIRECT_URI.equals(redirectUri)) {
            redirectUri = INSTALLED_REDIRECT_URI;
        }

        if (codeAuth != null) {
            // The request supplied an authorization header, so we process the credentials before
            // attempting to service the request. If the credentials are valid, googleUserId will
            // be assigned the Google ID of the authorized user, and the credentials will be
            // stored in the DataStore.
            GoogleTokenResponse tokenResponse = exchangeAuthorizationCode(codeAuth, redirectUri, response);

            if (tokenResponse != null) {

                // An ID Token is a cryptographically-signed JSON object encoded in base 64.
                googleUserId = parseIdToken(tokenResponse, response);

                if (googleUserId != null) {
                    user = Services.userDao.loadUserWithGoogleId(googleUserId);
                    // create user for the first time in datastore
                    if (user == null) {
                        user = new User();
                        user.setGoogleUserId(googleUserId);
                    }
                    user.setAccessToken(tokenResponse.getAccessToken());
                    user.setRefreshToken(tokenResponse.getRefreshToken());
                }
            }
        }

        if (idAuth != null) {
            // The request supplied a bearer token, so we verify the token before attempting to
            // service the request. The bearer token may be either an ID token or an access token for
            // requests from iOS devices, which currently cannot use authorization codes.
            // If the verification succeeds, googleUserId will be assigned the Google ID of the
            // authenticated user.
            googleUserId = verifyBearerToken(idAuth, response);
        }

        if (googleUserId != null) {
            // If a valid authentication header was supplied, or if valid credentials were associated
            // with this user, then we check to see if that same user is associated with the current
            // session before attempting to service the request. If not, a new session is created
            if (user == null) {
                user = Services.userDao.loadUserWithGoogleId(googleUserId);
            }
            // and associated with the authenticated/authorized user.
            user = authenticateSession(sessionId, googleUserId, user, request);
        }

        if (user == null) {
            // If the authentication or authorization step failed, then we were unable to retrieve
            // the associated user, so we check to see if there is a user associated with the
            // current session and attempt to service the request, based off of stored user credentials.
            User sessionUser = Services.userDao.loadUserWithSessionId(sessionId);
            if (sessionUser == null) {
                // The HTTP session does not have an authenticated user ID in it (or we were unable
                // to find the corresponding user in our database) and the request did not supply
                // an authorization header, so we return a request to authenticate with a bearer
                // token.
                logger.log(Level.INFO, "The session does not have an authenticated user, so return a 401 and request a bearer token.");
                response.addHeader(WWW_AUTHENTICATE, BEARER_SCHEME + " " + GOOGLE_REALM);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return null;
            } else {
                googleUserId = sessionUser.getGoogleUserId();
            }
        }

        // At this point, we have the correct user associated with the current authenticated session,
        // so we attempt to service the request.
        try {
            // We check the profile on every call to ensure that the cached Google user data is fresh,
            // since the Date check is cheap.
            return updateUserCache(googleUserId);
        } catch (CredentialNotFoundException e) {
            logger.log(Level.INFO,
                    "No credentials for Google user:" + googleUserId + "; request auth code with 401");
            // There are no associated credentials for the user, so we return a request to
            // authenticate with an authorization code.

            // There is no standard way for our server to request a new authorization code from
            // our client, so we use an non-standard scheme (X-OAuth-Code) to indicate that we
            // need a new refresh token.
            response.addHeader(CODE_SCHEME, GOOGLE_REALM);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return null;
        } catch (InvalidAccessTokenException e) {
            logger.log(Level.INFO,
                    "Access token expired for user" + googleUserId + "; request auth code with 401");
            // The refresh token was invalidated, so we return a request to authenticate with
            // an authorization code.

            // There is no standard way for our server to request a new authorization code from
            // our client, so we use an non-standard scheme (X-OAuth-Code) to indicate that we
            // need a new refresh token.
            response.addHeader(CODE_SCHEME, GOOGLE_REALM);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return null;
        } catch (IOException e) {
            logger.log(Level.INFO, "Something went wrong processing the request; return 500", e);
            // Likely a temporary network error
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return null;
        }
    }

    /**
     * Exchanges an authorization code for Google credentials, including an access and a refresh
     * token. If the exchange fails, an IOException is raised, and a 400 is specified in the
     * HTTP response, indicating that the authorization code was invalid. If the exchange succeeds,
     * a GoogleTokenResponse object is returned. Otherwise, null is returned to indicate a failure.
     */
    private GoogleTokenResponse exchangeAuthorizationCode(String authorization, String redirectUri,
                                                          HttpServletResponse response) {
        try {
            // Upgrade the authorization code into an access and refresh token.
            return createTokenExchanger(authorization, redirectUri).execute();
        } catch (TokenResponseException e) {
            //Failed to exchange authorization code.
            logger.log(Level.INFO, "Failed to exchange auth code; return 400", e);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return null;
        } catch (IOException e) {
            logger.log(Level.INFO, "Failed to exchange auth code; return 400", e);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return null;
        }
    }

    /**
     * Parses an ID token from a TokenResponse. If the parse fails, a 500 is specified and
     * null is returned, indicating that the ID token Google returned with a Credential object
     * is invalid. Otherwise, the Google user ID associated with the token is returned.
     */
    private String parseIdToken(GoogleTokenResponse tokenResponse, HttpServletResponse response) {
        try {
            // You can read the Google user ID in the ID token.
            GoogleIdToken idToken = tokenResponse.parseIdToken();
            return getGoogleIdFromIdToken(idToken);
        } catch (IOException e) {
            logger.log(Level.INFO, "Failed to parse ID token from tokenResponse object; return 500", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return null;
        }
    }

    /**
     * Retrieves the Google ID of a user out of an ID token.
     */
    private String getGoogleIdFromIdToken(GoogleIdToken idToken) {
        Payload payload = idToken.getPayload();
        return payload.getSubject();
    }


    /**
     * Validates the provided bearer token as an ID token. If the validation fails, an attempt
     * is made to validate the token as an access token. If the verifier fails, a 403 is
     * specified in the HTTP response, whereas an IOException thrown by a Google server indicates
     * that the token was invalid and a 400 is specified in the response.
     *
     * @return Google ID of the user the token is associated with; null if the token is invalid.
     */
    private String verifyBearerToken(String authorization, HttpServletResponse response) {
        String googlePlusId;
        GoogleIdToken idToken;
        try {
            // Attempt to parse the bearer token as an ID token. If this fails, pass the bearer token
            // along to be parsed as an access token.
            idToken = tokenRepo.parse(Services.JSON_FACTORY, authorization);
        } catch (IllegalArgumentException e) {
            logger.log(Level.INFO, "Failed to verify bearer token as ID token; attempting to verify as access token");
            return verifyAccessToken(authorization, response);
        } catch (IOException e) {
            logger.log(Level.INFO, "Failed to parse ID token; return 400", e);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return null;
        }

        try {
            // Verify the ID token before retrieving the Google ID of the user associated with the token
            if (idTokenVerifier.verify(idToken) && tokenRepo.verifyAudience(idToken, Collections.singletonList(Services.getClientId()))) {
                googlePlusId = getGoogleIdFromIdToken(idToken);
                return googlePlusId;
            } else {
                return null;
            }
        } catch (IOException e) {
            logger.log(Level.INFO, "Failed to verify ID token", e);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return null;
        } catch (GeneralSecurityException e) {
            logger.log(Level.INFO, "Failed to verify ID token", e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return null;
        }
    }

    /**
     * Validates the provided bearer token against the OAuth TokenInfo endpoint. If the HTTP request
     * fails, a 500 is specified in the response. If the token is invalid, a 400 is specified.
     * If the token is valid, a credential object is created and stored against the Google user
     * ID and that ID is returned. Otherwise, null is returned to indicate the failure.
     */
    String verifyAccessToken(String authorization, HttpServletResponse response) {
        TokenInfoResponse tokenResponse = null;
        try {
            // Form a request to the token info endpoint, since the Java client library does not
            // provide a method to validate an access token.
            HttpResponse httpResponse = Services.TRANSPORT.createRequestFactory()
                    .buildGetRequest(new GenericUrl(String.format(TOKEN_INFO_ENDPOINT, authorization)))
                    .execute();

            // Read the response into a TokenInfoResponse object.
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try {
                getContent(httpResponse.getContent(), out);

                tokenResponse = tokenRepo.fromJson(out);
            } catch (JsonParseException e) {
                logger.log(Level.INFO, "Unable to parse token info HTTP response; return 400", e);
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                return null;
            } finally {
                out.close();
            }
        } catch (HttpResponseException e) {
            logger.log(Level.INFO, "Token info HTTP request failed with error code", e);
            // The response code from the GET request was an error code.
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return null;
        } catch (IOException e) {
            logger.log(Level.INFO, "Response from token info HTTP request was malformed", e);
            // The response from the GET request was malformed or could not be read.
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return null;
        }

        String googlePlusId = null;
        // The client ID may not be a perfect match if the request came from an installed
        // application. Rather than verifying equality of the client IDs, we need to verify
        // that both client IDs belong to the same project. The easiest way to do this is to
        // compare the initial digit grouping from the client IDs, as this first part will
        // always be the project ID.
        Matcher tokenMatcher = CLIENT_ID_REGEX.matcher(tokenResponse.audience);
        Matcher clientIdMatcher = CLIENT_ID_REGEX.matcher(Services.getClientId());
        boolean tokenMatch = tokenMatcher.matches();
        boolean clientIdMatch = clientIdMatcher.matches();
        String tokenProject = "";
        String clientIdProject = "";
        if (tokenMatch && clientIdMatch) {
            tokenProject = tokenMatcher.group(1);
            clientIdProject = clientIdMatcher.group(1);
        }

        if (tokenResponse.expiresIn != null && tokenProject.equals(clientIdProject)) {
            googlePlusId = tokenResponse.userId;
            User user = Services.userDao.loadUserWithGoogleId(googlePlusId);
            user.setAccessToken(authorization);
            Services.userDao.updateUser(user);
        }
        return googlePlusId;
    }

    /**
     * Checks if the current session is associated with the specified Google user. If so, the
     * user object is returned. If not, the current session is discarded and a new one is
     * created and associated with the user object of the specified Google user.
     */
    private User authenticateSession(String sessionId, String googleUserId, User user, HttpServletRequest request) {
        if (user != null && sessionId.equalsIgnoreCase(user.getSessionId())) {
            // We have the correct user associated with the current session, so return the user object.
            return user;
        }

        if (user == null) {
            user = new User();
            user.setGoogleUserId(googleUserId);
        }

        // Invalidate the current session and authenticate the user for the new session.
        if (!request.getSession().isNew() && user.getSessionId() != null) {
            request.getSession().invalidate();
            user.setSessionId(request.getSession().getId());
        } else {
            user.setSessionId(sessionId);
        }

        Services.userDao.updateUser(user);

        return user;
    }

    /**
     * @return the authorization component of the header associated with the provided name based
     * on the provided regex pattern; null if the component does not exist
     */
    private String parseAuthorizationHeader(HttpServletRequest request, String headerName,
                                            Pattern pattern, int groupNumber) {
        String header = request.getHeader(headerName);
        String auth = null;
        if (header != null) {
            Matcher authMatcher = pattern.matcher(header);
            boolean authMatch = authMatcher.matches();
            if (authMatch) {
                if (authMatcher.groupCount() >= groupNumber) {
                    auth = authMatcher.group(groupNumber);
                }
            }
        }

        return auth;
    }

    /**
     * Updates the user's Google data in the Haiku+ DataStore, if the cached data is more
     * than one day old.
     *
     * @param googleId the current authenticated user
     * @return the User object stored in the DataStore
     */
    private User updateUserCache(String googleId) throws CredentialNotFoundException, IOException {
        User user = Services.userDao.loadUserWithGoogleId(googleId);
        if (user == null) {
            user = new User();
            user.setGoogleUserId(googleId);
        }

        // If the user's profile was updated less than one day ago, do nothing.
        if (!user.isDataFresh()) {
            fetchGoogleUserData(user);
            Services.userDao.updateUser(user);
        }

        return user;
    }

    /**
     * Performs the Google+ people.get API call to refresh a user's cached Google data. This data
     * should never be stored permanently and should be refreshed regularly (i.e. if it is older
     * than 24 hours).
     *
     * @param user the current authenticated user
     */
    private void fetchGoogleUserData(User user) throws CredentialNotFoundException, IOException {

        GoogleCredential credential = Services.createCredential(user.getAccessToken(), user.getRefreshToken());

        // Create google plus service to access user data
        Plus service = new Plus.Builder(Services.TRANSPORT, Services.JSON_FACTORY, credential).build();
        Person person = service.people().get("me").execute();

        // A Person resource contains many things, but in this sample, we chose to focus on the
        // Google ID, the display name, and the URLs of the user's profile and profile photo.
        user.setGoogleUserId(person.getId());
        user.setDisplayName(person.getDisplayName());
        user.setPhotoUrl(person.getImage().getUrl());
        user.setLastUpdated();
        user.setEmail(person.getEmails().get(0).getValue());

    }


    /**
     * Reads the content of an InputStream.
     *
     * @param inputStream  the InputStream to be read.
     * @param outputStream the content of the InputStream as a ByteArrayOutputStream.
     */
    private static void getContent(InputStream inputStream, ByteArrayOutputStream outputStream)
            throws IOException {
        // Read the response into a buffered stream
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        try {
            int readChar;
            while ((readChar = reader.read()) != -1) {
                outputStream.write(readChar);
            }
        } finally {
            reader.close();
        }
    }

    /**
     * Creates a token verifier object using the client secret values provided by client_secrets.json.
     *
     * @param authorization the authorization code to be exchanged for a bearer token once verified
     * @param redirectUri   the redirect URI to be used for token exchange, from the APIs console.
     */
    GoogleAuthorizationCodeTokenRequest createTokenExchanger(String authorization, String redirectUri) {
        return new GoogleAuthorizationCodeTokenRequest(Services.TRANSPORT,
                Services.JSON_FACTORY,
                Services.getClientId(),
                Services.getClientSecret(),
                authorization,
                redirectUri);
    }

    /**
     * Internal class used to monitor access and refresh tokens. If a token is invalid for an
     * API request, the tokens in the credential are inalidated and an InvalidAccessTokenException
     * is thrown to indicate that a new authorization code or bearer token is needed from the client.
     */
    public static class InvalidateRefreshTokenOnExpired implements CredentialRefreshListener {
        @Override
        public void onTokenErrorResponse(Credential credential, TokenErrorResponse error)
                throws IOException {
            if (error != null && "invalid_grant".equals(error.getError())) {
                credential.setAccessToken(null);
                credential.setRefreshToken(null);
                throw new InvalidAccessTokenException();
            }
        }

        @Override
        public void onTokenResponse(Credential credential, TokenResponse response) throws IOException {
        }
    }

    /**
     * Inner class to define the InvalidAccessTokenException, which is raised when a
     * refresh token fails to refresh the access token, indicating that the token has
     * expired or been invalidated and a new one is needed. Also may be raised when no
     * refresh token exists an the access token has expired, as is the case for the iOS client.
     */
    static class InvalidAccessTokenException extends IOException {
    }

    /**
     * Rebuilds a token from a JSON response from the OAuth 2.0 token info endpoint.
     */
    static class TokenInfoResponse extends Jsonifiable {
        String audience;
        String userId;
        String expiresIn;
    }

    /**
     * Used as an abstract factory for testing static and final method calls.
     */
    static class GoogleIdTokenRepository {
        public GoogleIdToken parse(JsonFactory jsonFactory, String idAuth) throws IOException {
            return GoogleIdToken.parse(jsonFactory, idAuth);
        }

        public boolean verifyAudience(GoogleIdToken idToken, List<String> audience) {
            return idToken.verifyAudience(audience);
        }

        public TokenInfoResponse fromJson(ByteArrayOutputStream out)
                throws UnsupportedEncodingException {
            return Jsonifiable.fromJson(out.toString("UTF-8"), TokenInfoResponse.class);
        }
    }
}
