package martinbradley.security;

import java.io.IOException;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import static martinbradley.security.JsonWebTokenVerifier.ValidationResult;

import mockit.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Response;
import java.util.Map;
import java.util.HashMap;
import javax.ws.rs.core.Cookie;

public class JsonWebTokenAuthFilterTest {
    private static Logger logger = LoggerFactory.getLogger(JsonWebTokenAuthFilterTest.class);
    JsonWebTokenAuthFilter impl = new JsonWebTokenAuthFilter();
    @Mocked ContainerRequestContext requestContext;
    @Mocked ServletContext servletContext;
    @Mocked ResourceInfo resourceInfo;
    @Mocked JsonWebTokenVerifier verifier;


    //@Mocked -ea -javaagent:/home/martin/.m2/repository/org/jmockit/jmockit/1.38/jmockit-1.38.jar

    @Mocked
    SecuredRestfulMethodHelper helper;

    @BeforeEach
    public void setMeUp() throws Exception {
        impl.resourceInfo = resourceInfo;
        impl.setServletContext(servletContext);
    }

    private void expectedAuth0Result(final boolean authResult)
        throws IOException, ServletException {
        new Expectations() {{

            verifier.isValidAccessRequest(anyString, anyString, (String[])any);

            ValidationResult valResult = new ValidationResult("userName", authResult);
            result = valResult;
        }};
    }

    private void expectBearerToken(final String aToken){
        new Expectations(){{
            requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
            result = "Bearer " + aToken;
            logger.debug("expectBearerToken 'Bearer ' "+ aToken);
        }};
    }
    private void expectCookeJWT(final String aToken) {
        new Expectations(){{
            Map<String, Cookie> cookieMap = new HashMap<>();
            Cookie jwtToken = new Cookie("jwtToken", aToken);
            cookieMap.put("jwtToken", jwtToken);

            requestContext.getCookies();
            result = cookieMap;
        }};
    }

    private void expectedGroups(String ... groups) throws Exception {
        new Expectations(){{
            helper.getGroups((ResourceInfo)any);
            result = groups;
        }};
    }

    private void timesAbortCalled(int aTimesCalled) {
        new Expectations(){{
            requestContext.abortWith( (Response)any);
            times = aTimesCalled;
        }};
    }

    @Test
    public void testSuccessfulWithHeaderToken()
        throws Exception {

        expectBearerToken("123");

        expectedGroups("admins");

        expectedAuth0Result(true);

        timesAbortCalled(0);

        new Expectations(){{
            requestContext.abortWith( (Response)any);
            times = 0;
        }};

        impl.filter(requestContext);
    }

    @Test
    public void testSuccessfulWithCookie()
        throws Exception {

        expectCookeJWT("123");

        expectedGroups("admins");

        expectedAuth0Result(true);

        timesAbortCalled(0);

        new Expectations(){{
            requestContext.abortWith( (Response)any);
            times = 0;
        }};

        impl.filter(requestContext);
    }

    @Test
    public void testFailed_NoGroups()
        throws Exception {

        expectBearerToken("123");

        expectedGroups();

        timesAbortCalled(1);

        impl.filter(requestContext);
    }
    @Test
    public void testFailed_NotAuthorized()
        throws Exception {

        expectBearerToken("123");

        expectedGroups("admins");

        expectedAuth0Result(false);

        timesAbortCalled(1);

        impl.filter(requestContext);
    }

    @Test
    public void testFailed_NoToken()
        throws Exception {

        timesAbortCalled(1);

        impl.filter(requestContext);
    }

}
