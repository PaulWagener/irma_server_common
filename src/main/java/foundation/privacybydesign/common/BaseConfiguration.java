package foundation.privacybydesign.common;

import com.google.gson.JsonSyntaxException;
import org.irmacard.api.common.util.GsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;

public class BaseConfiguration<T>  {
    // Override these in a static {} block
    public static Class<? extends BaseConfiguration> clazz;
    public static Logger logger = LoggerFactory.getLogger(BaseConfiguration.class);
    public static String filename = "config.json";
    public static String environmentVarPrefix = "IRMA_CONF_";
    public static String confDirEnvironmentVarName = "IRMA_CONF";
    public static boolean printOnLoad = false;
    public static boolean testing = false;

    // Return this from a static getInstance()
    public static BaseConfiguration instance;

    private static URI confPath;
    private static String confDirName = "irma_api_server";

    public static void load() {
        try {
            String json = new String(getResource(filename));
            instance = GsonUtil.getGson().fromJson(json, clazz);
            logger.info("Using configuration directory: " + BaseConfiguration.getConfigurationDirectory().toString());
        } catch (IOException|JsonSyntaxException e) {
            logger.info("WARNING: could not load configuration file. Using default values or environment vars");
            instance = GsonUtil.getGson().fromJson("{}", clazz);
        }
        instance.loadEnvVars();

        if (printOnLoad) {
            logger.info("Configuration:");
            logger.info(instance.toString());
        }
    }

    public static BaseConfiguration getInstance() {
        if (instance == null)
            load();
        return instance;
    }

    public static byte[] getResource(String filename) throws IOException {
        File file = new File(getConfigurationDirectory().resolve(filename));
        return convertSteamToByteArray(new FileInputStream(file), 2048);
    }

    public static byte[] convertSteamToByteArray(InputStream stream, int size) throws IOException {
        byte[] buffer = new byte[size];
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        int line;
        while ((line = stream.read(buffer)) != -1) {
            os.write(buffer, 0, line);
        }
        stream.close();

        os.flush();
        os.close();
        return os.toByteArray();
    }

    public static PrivateKey loadPrivateKey(String filename) throws KeyManagementException {
        try {
            return decodePrivateKey(getResource(filename));
        } catch (IOException e) {
            throw new KeyManagementException(e);
        }
    }

    public static PublicKey getPublicKey(String filename) throws KeyManagementException {
        try {
            return decodePublicKey(getResource(filename));
        } catch (IOException e) {
            throw new KeyManagementException(e);
        }
    }

    public static  PublicKey decodePublicKey(byte[] bytes) throws KeyManagementException {
        try {
            if (bytes == null || bytes.length == 0)
                throw new KeyManagementException("Could not read public key");

            X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
            throw new KeyManagementException(e);
        }
    }

    public PrivateKey getPrivateKey(String filename) throws KeyManagementException {
        try {
            return decodePrivateKey(getResource(filename));
        } catch (IOException e) {
            throw new KeyManagementException(e);
        }
    }

    public static PrivateKey decodePrivateKey(byte[] rawKey) throws KeyManagementException {
        try {
            if (rawKey == null || rawKey.length == 0)
                throw new KeyManagementException("Could not read private key");

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(rawKey);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (NoSuchAlgorithmException |InvalidKeySpecException e) {
            throw new KeyManagementException(e);
        }
    }

    /**
     * Override configuration with environment variables, if set
     * Uses reflection to set variables, because otherwise it would be impossible to set all variable at once in a loop
     */
    public void loadEnvVars() {
        for (Field f : BaseConfiguration.clazz.getDeclaredFields()) {
            if ( Modifier.isTransient(f.getModifiers()) || Modifier.isStatic(f.getModifiers())) {
                // Skip transient and static fields
                continue;
            }

            Object envValue = getEnv(environmentVarPrefix + f.getName(), f.getType());
            if (envValue != null) {
                try {
                    f.set(this, envValue);
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Obtain an environment variable and parse it to the right type
     * @param confEntry name of environment variable
     * @param cls class to be parsed into (either Integer, Boolean, String, HashMap)
     * @param <T> type of the variable
     * @return a parsed variable in the right type (T) or null if environment variable isn't set
     */
    public static <T> T getEnv(String confEntry, Class<T> cls) {
        confEntry = confEntry.toUpperCase();
        String env = System.getenv(confEntry);
        if (env== null || env.length() == 0) {
            return null;
        }

        T overrideValue;
        if (cls == int.class) {
            try {
                Integer parsed = Integer.parseInt(env);
                overrideValue = (T) parsed;
            } catch (NumberFormatException e) {
                logger.warn("Could not parse config entry as int: " + confEntry + " with value: " + env);
                return null;
            }
        } else if (cls == boolean.class) {
            Boolean parsed = Boolean.parseBoolean(env);
            overrideValue = (T) parsed;
        } else if (cls == String.class) {
            overrideValue = cls.cast(env);
        } else if (cls == HashMap.class){ // Try to parse as hashmap for authorized_??? entries
            try {
                overrideValue = cls.cast(GsonUtil.getGson().fromJson(env, cls));
            } catch (JsonSyntaxException e) {
                logger.warn("Could not parse config entry as json: " + confEntry + " with value: " + env);
                return null;
            }
        } else {
            throw new IllegalArgumentException("Invalid class specified, must be one of: Integer, Boolean, String, HashMap");
        }

        logger.info("Overriding config entry " + confEntry + " with value: " + env);
        return overrideValue;
    }

    /**
     * If a path was set in the $confDirEnvironmentVarName environment variable, return it
     */
    public static URI getEnvironmentVariableConfDir() throws URISyntaxException {
        String envDir = System.getenv(confDirEnvironmentVarName);
        if (envDir == null || envDir.length() == 0)
            return null;

        if (!envDir.startsWith("file://"))
            envDir = "file://" + envDir;
        if (!envDir.endsWith("/"))
            envDir += "/";

        return new URI(envDir);
    }

    /**
     * Returns true if the specified path is a valid configuration directory. A directory
     * is considered a valid configuration directory if it contains a file called $filename.
     */
    public static boolean isConfDirectory(URI candidate) {
        return candidate != null && new File(candidate.resolve(filename)).isFile();
    }

    /**
     * Get the path to the Java resources directory, i.e., src/main/resources or src/test/resources;
     * note that it must contain the file called $filename or "config.test.json" for this to work
     */
    public static URI GetJavaResourcesDirectory() throws URISyntaxException {
        // The only way to actually get the resource folder, as opposed to the classes folder,
        // seems to be to ask for an existing file or directory within the resources. That is,
        // BaseConfiguration.class.getClassLoader().getResource("/") or variants thereof
        // give an incorrect path.
        String testfile = BaseConfiguration.testing ? "config.test.json" : filename;
        URL url = BaseConfiguration.class.getClassLoader().getResource(testfile);
        if (url != null) // Construct an URI of the parent path
            return new URI("file://" + new File(url.getPath()).getParent() + "/");
        else
            return null;
    }

    /**
     * Get the configuration directory.
     * @throws IllegalStateException If no suitable configuration directory was found
     * @throws IllegalArgumentException If the path from the $confDirEnvironmentVarName environment variable was
     *                                  not a valid path
     */
    public static URI getConfigurationDirectory() throws IllegalStateException, IllegalArgumentException {
        if (confPath != null)
            return confPath;

        try {
            // If we're running unit tests, only accept src/test/resources
            URI resourcesCandidate = GetJavaResourcesDirectory();
            if (BaseConfiguration.testing) {
                if (resourcesCandidate != null) {
                    logger.info("Running tests: taking src/test/resources as configuration directory");
                    confPath = resourcesCandidate;
                    return confPath;
                }
                else {
                    throw new IllegalStateException("No configuration found in in src/test/resources. " +
                            "(Have you run `git submodule init && git submodule update`?)");
                }
            }

            // If a path was given in the $confDirEnvironmentVarName environment variable, prefer it
            URI envCandidate = getEnvironmentVariableConfDir();
            if (envCandidate != null) {
                if (isConfDirectory(envCandidate)) {
                    logger.info("Taking configuration directory specified by environment variable " + confDirEnvironmentVarName);
                    confPath = envCandidate;
                    return confPath;
                } else {
                    // If the user specified an incorrect path (s)he will want to know, so bail out here
                    throw new IllegalArgumentException("Specified path in " + confDirEnvironmentVarName
                            + " is not a valid configuration directory");
                }
            }

            // See if a number of other fixed candidates are suitable
            ArrayList<URI> candidates = new ArrayList<>(4);
            candidates.add(resourcesCandidate);
            candidates.add(new URI("file:///etc/" + confDirName + "/"));
            candidates.add(new URI("file:///C:/" + confDirName + "/"));
            candidates.add(new File(System.getProperty("user.home")).toURI().resolve(confDirName + "/"));

            for (URI candidate : candidates) {
                if (isConfDirectory(candidate)) {
                    confPath = candidate;
                    return confPath;
                }
            }

            throw new IllegalStateException("No valid configuration directory found");
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public String toString() {
        return GsonUtil.getGson().toJson(this);
    }
}
