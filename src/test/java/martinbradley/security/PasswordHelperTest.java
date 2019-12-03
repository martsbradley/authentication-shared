package martinbradley.security;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;


public class PasswordHelperTest {

    private static final Logger logger = LoggerFactory.getLogger(PasswordHelper.class);
    @Test
    public void makePassword() {
        PasswordHelper ph = new PasswordHelper();
        String salt = ph.generateSalt();
        String passwordHash = ph.hashPassword("lisa", salt);
        logger.info("salt " + salt);
        logger.info("passwordHash " + passwordHash);
    }

    @Test
    public void patient_load_not_found_404() {

        PasswordHelper ph = new PasswordHelper();
        String hash  = ph.hashPassword("marty", "bradley");

        logger.info("Hash is length:" + hash.length());
        assertThat(hash, is("7dbc8624d4b298f55a0c70a166765fb1a189fefc1013007e413d53211baa3b28"));
    }
}

