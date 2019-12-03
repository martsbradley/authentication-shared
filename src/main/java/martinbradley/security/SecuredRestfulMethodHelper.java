package martinbradley.security;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.ws.rs.container.ResourceInfo;
import java.lang.reflect.Method;
import java.util.Arrays;

public class SecuredRestfulMethodHelper {

    private static Logger logger = LoggerFactory.getLogger(SecuredRestfulMethodHelper.class);
    public SecuredRestfulMethodHelper() {
    }

    public String[] getGroups(ResourceInfo aResourceInfo) throws Exception {

        Method method = aResourceInfo.getResourceMethod();
        String[] groups = new String[0];

        if (method != null) {
            SecuredRestfulMethod secured = method.getAnnotation(SecuredRestfulMethod.class);
            groups =  secured.groups();  
            logger.info("Annotation groups are: " + Arrays.toString(groups));  
        }
        else {
            logger.warn("Method is null!!!");
        }

        if (groups == null || groups.length == 0) {
            throw new Exception("No groups defined");
        }
        return groups;
    }
}
