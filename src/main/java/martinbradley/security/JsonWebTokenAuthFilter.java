package martinbradley.security;

import com.auth0.jwk.JwkException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.servlet.ServletContext;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.*;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.security.Principal;
import java.security.PublicKey;
import java.util.Map;
import static martinbradley.security.JsonWebTokenVerifier.ValidationResult;

@SecuredRestfulMethod
@Provider
@Priority(Priorities.AUTHENTICATION)
public class JsonWebTokenAuthFilter implements ContainerRequestFilter {

  private static Logger logger = LoggerFactory.getLogger(JsonWebTokenAuthFilter.class);
    private static final String REALM = "example";
    private static final String AUTHENTICATION_SCHEME = "Bearer";
    @Context ResourceInfo resourceInfo;

    private JsonWebTokenVerifier verifier;

    @Context
    public void setServletContext(ServletContext aContext) throws JwkException {

        String issuer = AuthenticationConstants.AUTH_ISSUER.getValue();

        KeyStoreLoader keyLoader = new KeyStoreLoader(AuthenticationConstants.AUTH_ISSUER.getValue(),
                                                      AuthenticationConstants.AUTH_DOMAIN.getValue());
        PublicKey publicKey = keyLoader.getPublicKey();

        verifier = new JsonWebTokenVerifier(issuer, publicKey);
    }

    @Override
    public void filter(ContainerRequestContext requestContext)
        throws IOException {

        String authToken = getAuthToken(requestContext);

        if (authToken.isEmpty()) {
            logger.warn("JWT token missing.");
            abortWithUnauthorized(requestContext);
            return;
        }

        try {
            final ValidationResult validationOutcome = validateToken(authToken);

            if (validationOutcome.isVerified() == false) {
                logger.warn("abortWithUnauthorized invalid token");
                abortWithUnauthorized(requestContext);
            }
            else {
                addUserPrinciple(validationOutcome.getUserName(), requestContext);
            }

        } catch (Exception e) {
            logger.warn("abortWithUnauthorized exception ",e.getMessage());
            abortWithUnauthorized(requestContext);
        }
    }

    private void addUserPrinciple(final String userName, ContainerRequestContext request) {

        logger.info("Add Principle " + userName);

        Principal user  = new Principal() {
            @Override
            public String getName() {
                return userName;
            }
        };
        // or simple but not the best
        request.setSecurityContext( new SecurityContext() {
            @Override
            public boolean isUserInRole(String role) {
                return true; // check roles if you need ...
            }
            @Override
            public boolean isSecure() {
                return false; // check HTTPS
            }
            @Override
            public Principal getUserPrincipal() {
                return user;
            }
            @Override
            public String getAuthenticationScheme() {
                return null; // ...
            }
        });
    }

    private String getAuthToken(ContainerRequestContext requestContext) {
        String token = getCookieAuthToken(requestContext);

        if (token.isEmpty()){
            token = getHeaderAuthToken(requestContext);
        }
        return token;
    }

    private String getCookieAuthToken(ContainerRequestContext requestContext) {

        Map<String, Cookie> cookies  = (Map<String, Cookie>)requestContext.getCookies();
        for (String key : cookies.keySet()){
            logger.debug("Got cookie named "+ key);
        }
        logger.debug("Cookie map has " + cookies.size() );

        String token = "";

        Cookie jwtCookie = cookies.get("jwtToken");

        // If the cookie is
        if (jwtCookie != null) {
            token = jwtCookie.getValue();
        }
        return token;
    }

    private String getHeaderAuthToken(ContainerRequestContext requestContext) {
        String authorizationHeader =
                requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);

        if (!isTokenBasedAuthentication(authorizationHeader)) {
            logger.warn("JWT token not in header.");
            return "";
        }

        String token = authorizationHeader
                            .substring(AUTHENTICATION_SCHEME.length())
                            .trim();
        return token;
    }


    private void abortWithUnauthorized(ContainerRequestContext requestContext) {

        logger.warn("Aborting with UNAUTHORIZED");
        // Abort the filter chain with a 401 status code response
        // The WWW-Authenticate header is sent along with the response
        requestContext.abortWith(
                Response.status(Response.Status.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE,
                                AUTHENTICATION_SCHEME + " realm=\"" + REALM + "\"")
                        .build());
    }

    private boolean isTokenBasedAuthentication(String authorizationHeader) {

        // Check if the Authorization header is valid
        // It must not be null and must be prefixed with "Bearer" plus a
        // whitespace The authentication scheme comparison must be
        // case-insensitive
        return authorizationHeader != null && authorizationHeader.toLowerCase()
                    .startsWith(AUTHENTICATION_SCHEME.toLowerCase() + " ");
    }

    private ValidationResult validateToken(String token) throws Exception {
        SecuredRestfulMethodHelper helper = new SecuredRestfulMethodHelper();

        String[] requiredGroups = helper.getGroups(resourceInfo);

        ValidationResult result = verifier.isValidAccessRequest(token,
                                                        AuthenticationConstants.AUTH_DOMAIN.getValue(),
                                                        requiredGroups);
        boolean isValid = result.isVerified();
        logger.warn("Valid token ?" + isValid);
        return result;
    }



}
