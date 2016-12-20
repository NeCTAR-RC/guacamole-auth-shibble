/*
 * Copyright (C) 2013 Glyptodon LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.nectar.guacamole.net.auth.shibble;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Map;
import java.util.Enumeration;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleServerException;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.environment.LocalEnvironment;
import org.glyptodon.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.properties.FileGuacamoleProperty;
import org.glyptodon.guacamole.properties.IntegerGuacamoleProperty;
import org.glyptodon.guacamole.properties.StringGuacamoleProperty;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

/**
 * Shibble authentication in Guacamole. All users accessing Guacamole are
 * automatically added to all configuration profiles read from the XML file
 * defined by `shibble-config` in the Guacamole configuration file
 * (`guacamole.properties`).
 *
 *
 * Example `guacamole.properties`:
 *
 *  shibble-config: /etc/guacamole/shibble-config.xml
 *
 *
 * Example `shibble-config.xml`:
 *
 *  <configs>
 *    <config name="my-rdp-server" protocol="rdp">
 *      <param name="hostname" value="my-rdp-server-hostname" />
 *      <param name="port" value="3389" />
 *    </config>
 *  </configs>
 *
 * @author Laurent Meunier
 */
public class ShibbleAuthenticationProvider extends SimpleAuthenticationProvider {

    /**
     * Logger for this class.
     */
    private Logger logger = LoggerFactory.getLogger(ShibbleAuthenticationProvider.class);

    /**
     * JDBC driver.
     */
    static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";

    /**
     * Map of all known configs, indexed by identifier.
     */
    private Map<String, GuacamoleConfiguration> configs;

    /**
     * The last time the configuration XML was modified, as milliseconds since
     * UNIX epoch.
     */
    private long configTime;

    /**
     * Guacamole server environment.
     */
    private final Environment environment;
    
    /**
     * The XML file to read the configuration from.
     */
    public static final FileGuacamoleProperty SHIBBLE_CONFIG = new FileGuacamoleProperty() {

        @Override
        public String getName() {
            return "shibble-config";
        }

    };


    /**
     * The default filename to use for the configuration, if not defined within
     * guacamole.properties.
     */
    public static final String DEFAULT_SHIBBLE_CONFIG = "shibble-config.xml";


    /**
     * The name of the environment varible which includes the user attribute
     */
    public static final StringGuacamoleProperty SHIBBOLETH_USERNAME_HEADER = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "shbboleth-username-header"; }

    };


    /**
     * The hostname of the MySQL server hosting the Guacamole authentication 
     * tables.
     */
    public static final StringGuacamoleProperty MYSQL_HOSTNAME = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "mysql-hostname"; }

    };

    /**
     * The port number of the MySQL server hosting the Guacamole authentication 
     * tables.
     */
    public static final IntegerGuacamoleProperty MYSQL_PORT = new IntegerGuacamoleProperty() {

        @Override
        public String getName() { return "mysql-port"; }

    };

    /**
     * The name of the MySQL database containing the Guacamole authentication 
     * tables.
     */
    public static final StringGuacamoleProperty MYSQL_DATABASE = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "mysql-database"; }

    };

    /**
     * The username that should be used when authenticating with the MySQL
     * database containing the Guacamole authentication tables.
     */
    public static final StringGuacamoleProperty MYSQL_USERNAME = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "mysql-username"; }

    };

    /**
     * The password that should be used when authenticating with the MySQL
     * database containing the Guacamole authentication tables.
     */
    public static final StringGuacamoleProperty MYSQL_PASSWORD = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "mysql-password"; }

    };

    /**
     * Creates a new ShibbleAuthenticationProvider that does not perform any
     * authentication at all. All attempts to access the Guacamole system are
     * presumed to be authorized.
     *
     * @throws GuacamoleException
     *     If a required property is missing, or an error occurs while parsing
     *     a property.
     */
    public ShibbleAuthenticationProvider() throws GuacamoleException {
        environment = new LocalEnvironment();
    }

    @Override
    public String getIdentifier() {
        return "shibble";
    }

    /**
     * Retrieves the configuration file, as defined within guacamole.properties.
     *
     * @return The configuration file, as defined within guacamole.properties.
     * @throws GuacamoleException If an error occurs while reading the
     *                            property.
     */
    private File getConfigurationFile() throws GuacamoleException {

        // Get config file, defaulting to GUACAMOLE_HOME/shibble-config.xml
        File configFile = environment.getProperty(SHIBBLE_CONFIG);
        if (configFile == null)
            configFile = new File(environment.getGuacamoleHome(), DEFAULT_SHIBBLE_CONFIG);

        return configFile;

    }

    public synchronized void init() throws GuacamoleException {

        // Get configuration file
        File configFile = getConfigurationFile();
        logger.debug("Reading configuration file: \"{}\"", configFile);

        // Parse document
        try {

            // Set up parser
            ShibbleAuthConfigContentHandler contentHandler = new ShibbleAuthConfigContentHandler();

            XMLReader parser = XMLReaderFactory.createXMLReader();
            parser.setContentHandler(contentHandler);

            // Read and parse file
            Reader reader = new BufferedReader(new FileReader(configFile));
            parser.parse(new InputSource(reader));
            reader.close();

            // Init configs
            configTime = configFile.lastModified();
            configs = contentHandler.getConfigs();

        }
        catch (IOException e) {
            throw new GuacamoleServerException("Error reading configuration file.", e);
        }
        catch (SAXException e) {
            throw new GuacamoleServerException("Error parsing XML file.", e);
        }

    }

    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials credentials) throws GuacamoleException {

        // Check mapping file mod time
        File configFile = getConfigurationFile();
        if (configFile.exists() && configTime < configFile.lastModified()) {

            // If modified recently, gain exclusive access and recheck
            synchronized (this) {
                if (configFile.exists() && configTime < configFile.lastModified()) {
                    logger.debug("Configuration file \"{}\" has been modified.", configFile);
                    init(); // If still not up to date, re-init
                }
            }

        }

        HttpServletRequest request = credentials.getRequest();
        if (request == null)
            return null;

        // Header property
        String shibbolethUsernameHeader;
        if (environment.getProperty(SHIBBOLETH_USERNAME_HEADER) == null)
            shibbolethUsernameHeader = "remote_user";
        else
            shibbolethUsernameHeader = environment.getProperty(SHIBBOLETH_USERNAME_HEADER);

        // TODO: Fix to use request environment variable
        String remoteUser = request.getHeader(shibbolethUsernameHeader);
        if (remoteUser == "null") {
            logger.error("Remote user not found.");
            return null;
        }
        else {
            logger.info("Found remote user: '{}'", remoteUser);
        }

        // MySQL properties
        String mysqlHost = environment.getRequiredProperty(MYSQL_HOSTNAME);
        String mysqlDatabase = environment.getRequiredProperty(MYSQL_DATABASE);
        String mysqlUsername = environment.getRequiredProperty(MYSQL_USERNAME);
        String mysqlPassword = environment.getRequiredProperty(MYSQL_PASSWORD);

        // MySQL port
        int mysqlPort;
        if (environment.getProperty(MYSQL_PORT) == null)
            mysqlPort = 3306;
        else
            mysqlPort = environment.getProperty(MYSQL_PORT);

        Connection con = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            //initialize the jdbc driver
            Class.forName(JDBC_DRIVER);
            con = DriverManager.getConnection("jdbc:mysql://" + mysqlHost + ":" + mysqlPort + "/" + mysqlDatabase, mysqlUsername, mysqlPassword);
            String query = "SELECT password FROM user where lower(user.email) = ?";
            stmt = con.prepareStatement(query);
            stmt.setString(1, remoteUser.toLowerCase());

            rs = stmt.executeQuery();

            // Add our user credentials to every config 
            while (rs.next()) {
                String remoteUserPassword = rs.getString("password");
                for (Map.Entry<String, GuacamoleConfiguration> entry : configs.entrySet()) {
                    logger.info("Adding user '{}' to configuration '{}'", remoteUser, entry.getKey());
                    GuacamoleConfiguration config = entry.getValue();
                    config.setParameter("username", remoteUser.toLowerCase());
                    config.setParameter("password", remoteUserPassword);
                }
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw new GuacamoleException("failed to connect to database", e);
        } finally {
            try {
                if (rs != null)
                    rs.close();
                if (stmt != null)
                    stmt.close();
                if (con != null)
                    con.close();
            } catch (Exception f) {
                logger.warn("failed to close database.", f);
            }
        }

        // If no mapping available, report as such
        if (configs == null)
            throw new GuacamoleServerException("Configuration could not be read.");

        return configs;

    }
}
