package martinbradley.security;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Set;

import org.json.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class JsonWebToken {
    private final String issuer;
    private final long iat;
    private final long exp;
    private final String scope;
    private final String namespace;
    private final String[] groups;
    private final String subject;
    private static final Logger logger = LoggerFactory.getLogger(JsonWebToken.class);
    private String jwtAuthTokenValue = "";

    private JsonWebToken(Builder aBuilder) {
        issuer    = aBuilder.issuer;
        iat       = aBuilder.iat;
        exp       = aBuilder.exp;
        scope     = aBuilder.scope;
        namespace = aBuilder.namespace;
        groups    = aBuilder.groups;
        subject   = aBuilder.subject;
    }

    public String getHeader() {
        JSONObject header = new JSONObject();
        header.put("alg", "RS256");
        header.put("typ", "JWT");

        return header.toString();
    }
    public String getPayload() {

        logger.debug("**Building Payload");
        JSONObject payload = new JSONObject();
        payload.put("name", "Martin Bradley");
        payload.put("iss", issuer);
        payload.put("scope", scope);
        payload.put("iat", new Long(iat));
        payload.put("exp", new Long(exp));
        payload.put("sub", subject);
        logger.warn("Created token with subject " + subject);
        //payload.put("sub","1234567890");

        logger.debug("payload" + payload.toString());

        if (namespace != null && groups != null) {
            JSONArray groupsArray = new JSONArray(groups);
            JSONObject group = new JSONObject();

            group.put("groups",groupsArray);

            payload.put(namespace, group);
        }

        String strPayload = payload.toString();
        logger.debug("payload done " + strPayload);

        return strPayload;
    }

    public String[] getGroups() {
        return groups;
    }

    /**
     * This method delivers the final product.
     * @return
     */
    @Override
    public String toString() {
        return jwtAuthTokenValue;
    }

    public void sign(KeyPair keyPair) throws Exception {

        String header =  getHeader();
        String payload = getPayload();

        logger.info("header is  "+ header);
        logger.info("payload is  "+ payload);


        String encodedHeader  = base64Encode(header);
        String encodedPayload = base64Encode(payload);

        String toBeSigned = encodedHeader + "." + encodedPayload;
        String signature = signIt(keyPair, toBeSigned);
        this.jwtAuthTokenValue = toBeSigned + "." + signature;

        logger.debug("Result is "+ this.jwtAuthTokenValue);
    }

    private String signIt(KeyPair keyPair, String aToBeSigned)
            throws Exception {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");

            signer.initSign(keyPair.getPrivate());
            signer.update(aToBeSigned.getBytes());
            byte[] signedBytes = signer.sign();

            Base64.Encoder encoder = Base64.getEncoder();
            byte[] encodedBytes = encoder.encode(signedBytes);

            String signature = new String(encodedBytes);
            return signature;
        } catch (NoSuchAlgorithmException e) {
            logger.warn("No such signature", e);
            throw e;
        }
        catch (Exception e) {
            logger.warn("Error ", e);
            throw e;
        }
    }

    private String base64Encode(String aInput) {
        Base64.Encoder encoder = Base64.getEncoder();

        byte[] encodedBytes = encoder.encode(aInput.getBytes());

        String output = new String(encodedBytes);
        return output;
    }

    public static class Builder {
        String issuer;
        long iat;
        long exp;
        String scope;
        String namespace;
        String[] groups;
        String subject;

        public Builder setIssuer(String aIssuer) {
            this.issuer = aIssuer;
            return this;
        }
        public Builder setIat(long aIat) {
            this.iat = aIat;
            return this;
        }
        public Builder setExp(long aExp){
            this.exp = aExp;
            return this;
        }
        public Builder setScope(String aScope){
            this.scope = aScope;
            return this;
        }
        public Builder setGroups(String namespace, String ... groups) {
            this.namespace = namespace;
            this.groups = groups;
            return this;
        }
        public Builder setSubject(String aSubject) {
            this.subject = aSubject;
            return this;
        }
        public JsonWebToken build(){
            return new JsonWebToken(this);
        }
    }
}
