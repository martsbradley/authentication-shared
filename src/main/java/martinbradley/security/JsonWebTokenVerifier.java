package martinbradley.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static java.util.stream.Collectors.toSet;

public class JsonWebTokenVerifier {
    private final JWTVerifier verifier;
    private static Logger logger = LoggerFactory.getLogger(JsonWebTokenVerifier.class);

    public JsonWebTokenVerifier(String aIssuer,
                                PublicKey aPublicKey) {

        RSAPrivateKey privateKey = null;// Not needed, here we only verify tokens.

        final Algorithm algorithm = Algorithm.RSA256((RSAPublicKey)aPublicKey, 
                                                     privateKey);
        logger.info("Created Verifier with issuer '" + aIssuer + "'");
        verifier = JWT.require(algorithm)
                      .withIssuer(aIssuer)
                      .build(); 
    }

    public boolean tokenIsValid(String token) {
        
        DecodedJWT result = getToken(token);
        return result != null;
    }

    public Set<String> readGroups(String token, 
                           String namespace) throws Exception {

        DecodedJWT jwt = getToken(token);
        if (jwt == null) {
            throw new Exception("Token invalid");
        }

        Set<String> allowedGroups = allowedGroups(jwt, namespace);

        return allowedGroups;
    }
    public ValidationResult isValidAccessRequest(String token,
                                        String namespace,
                                        String ... aRequiredGroups) {
        DecodedJWT jwt = getToken(token);

        if (jwt == null ) {
            logger.warn("jwt is null");
            return ValidationResult.failed();
        }

        if (aRequiredGroups.length == 0) {
            logger.warn("Need to specify groups when using security");
            return ValidationResult.failed();
        }

        Set<String> allowedGroups = allowedGroups(jwt, namespace);

        Set<String> requiredGroups = new HashSet<>(
                                           Arrays.asList(aRequiredGroups));
        for (String group: allowedGroups) {
            logger.warn("Allowed group name '" +group + "'");
        }

        for (String group: requiredGroups) {
            logger.warn("Required group name '" +group + "'");
        }

        boolean isValid = allowedGroups.containsAll(requiredGroups);

        logger.warn("isValidAccessRequest returning " + isValid);
        if (!isValid) {
            logger.warn("Authorization failed for " + token);
        }

        String userName = jwt.getSubject();

        ValidationResult result = new ValidationResult(userName, isValid);

        return result;
    }
    /*
     *
  {
  "https://gorticrum.com/user_authorization": {
    "groups": [
      "adminGroup"
    ]
  },
  "iss": "https://myeducation.eu.auth0.com/",
  "sub": "auth0|5c1d5347b171c1019044870e",
  "aud": [
    "http://localhost:8080/firstcup/hospital/rest",
    "https://myeducation.eu.auth0.com/userinfo"
  ],
  "iat": 1548274059,
  "exp": 1a548277659,
  "azp": "eoK8GT2cFHcYWIbdGy-7qm9Wx5sanGkh",
  "scope": "openid profile email read:patients"
}
*/
    @SuppressWarnings("unchecked")
    private Set<String> allowedGroups(DecodedJWT aJwt,
                                      String aNamespace) {
        Map<String, Claim> claims = aJwt.getClaims();

        Set<String> allowedGroups = new HashSet<>();

        if (claims.containsKey(aNamespace)) {
            Claim groupsClaim = claims.get(aNamespace);

            Map<String,Object> map = groupsClaim.asMap();

            String GROUPS_NAME = "groups";

            if (map != null && map.containsKey(GROUPS_NAME)) {
                List<String> groups = Collections.emptyList();

                Object value = null;
                try {
                    value = map.get(GROUPS_NAME);

                  groups = (List<String>) value;
                } 
                catch(ClassCastException e) {
                    logger.warn("Could not cast " + value , e);
                }
                allowedGroups = new HashSet<>(groups);
            }
            else {
                logger.warn("Namespace '" + aNamespace + " does not contain " + GROUPS_NAME);
            }
        }
        else {
            logger.warn("Namespace '" + aNamespace + "' not found in claims");
        }
        return allowedGroups;
    }

    private DecodedJWT getToken(String token) {
        DecodedJWT jwt = null;
        try {
            jwt = verifier.verify(token);
        } catch (JWTVerificationException exception){
            logger.warn("JWT Not valid : "+ exception.getMessage());
        }
        return jwt;
    }

    public boolean validTokenHasScopes(String token, String ... scopes) {
        try {
            if (scopes == null || scopes.length == 0) {
                logger.warn("A scope is mandatory");
                return false;
            }
            logger.debug("Checking token :" + token);
            DecodedJWT jwt = verifier.verify(token.toString());
            
            logger.debug("Decoded successfully");

            if (!jwtHasRequiredScope(jwt, scopes)) {
                return false;
            }

            return true;
        } catch (JWTVerificationException exception){
            logger.warn("JWT Not valid : "+ exception.getMessage());
        }
        return false;
    }

    private boolean jwtHasRequiredScope(DecodedJWT aJwt,
                                     String ... aRequiredScope) {

        Set<String> tokenScopes = scopesFromJwt(aJwt);

        List<String> required = Arrays.asList(aRequiredScope);

        boolean isValid = tokenScopes.containsAll(required);

        if (!isValid) {
            logger.warn("Missing claim scope.\ntokenScope " + tokenScopes);
            logger.warn("required " + required);
        }
        return isValid;
    }

    private Set<String> scopesFromJwt(DecodedJWT aJwt) {
        Set<String> scopes = new HashSet<>();

        Map<String, Claim> claims = aJwt.getClaims();
        Claim claim = claims.get("scope");

        if (claim != null) {
            String[] allowedScopes = claim.asString().split(" ");
            scopes = Arrays.stream(allowedScopes).collect(toSet());
        }
        return scopes;
    }

    public static class ValidationResult {
        final String userName;
        final boolean verified;
        ValidationResult(String userName, boolean verified) {
            this.userName = userName;
            this.verified = verified;
        }

        public static ValidationResult failed() {
            return new ValidationResult("", false);
        }

        public String getUserName() {
            return userName;
        }

        public boolean isVerified() {
            return verified;
        }
    }
}
