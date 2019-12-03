package martinbradley.security;


import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public enum AuthenticationConstants {
    AUTH_ISSUER,
    AUTH_KEYSTORE,
    AUTH_DOMAIN, // eg "gorticrum.com";
    AUTH_KEYSTORE_PASSWD;

    private static Logger logger = LoggerFactory.getLogger(AuthenticationConstants.class);
    public String getValue() {

        final String name = name();

        Map<String, String> env = System.getenv();

        if (!env.containsKey(name)){
            logger.warn("Missing environment variable for " + name);
            throw new RuntimeException("Missing environment variable for " + name);
        }

        return env.get(name);
    }
}
