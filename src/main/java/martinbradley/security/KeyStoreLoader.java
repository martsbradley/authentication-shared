package martinbradley.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.inject.Model;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;

@Model
public class KeyStoreLoader {
    private final KeyPair keyPair;
    private String issuer = "";
    private String namespace ="";
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreLoader.class);

    public KeyStoreLoader(String issuer, String namespace) {

        this.issuer = issuer;//AuthenticationConstants.AUTH_ISSUER.getValue();
        this.namespace = namespace;//AuthenticationConstants.AUTH_DOMAIN.getValue();

        keyPair = loadKeyStore();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    private KeyPair loadKeyStore() {

        String keyStorePath = AuthenticationConstants.AUTH_KEYSTORE.getValue();
        char [] keyStorePassword = AuthenticationConstants.AUTH_KEYSTORE_PASSWD.getValue().toCharArray();;

        KeyPair keyPair = getKeyPair(keyStorePath, keyStorePassword);
        return keyPair;
    }

    public KeyPair getKeyPair(String keyStorePath, char[] keyStorePassword) {

        try (FileInputStream is = new FileInputStream(keyStorePath)) {

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, keyStorePassword);

            String alias = "signFiles";

            Key key = keystore.getKey(alias, keyStorePassword);
            Arrays.fill(keyStorePassword, '0');

            if (key instanceof PrivateKey) {
                // Get certificate of public key
                Certificate cert = keystore.getCertificate(alias);

                // Get public key
                PublicKey publicKey = cert.getPublicKey();
                logger.info("Public Key is " + publicKey);

                // Return a key pair
                return new KeyPair(publicKey, (PrivateKey) key);
            } else {
                logger.warn("Cannot create keyPair from keystore :" + keyStorePath);
                throw new RuntimeException("Unable to load keystore from " + keyStorePath);
            }
        }
        catch(Exception e) {
            logger.warn("Cannot create keyPair from keystore :" + keyStorePath);
            logger.warn("Issue was ", e);
            throw new RuntimeException("Unable to load keystore from " + keyStorePath);
        }
    }
}
