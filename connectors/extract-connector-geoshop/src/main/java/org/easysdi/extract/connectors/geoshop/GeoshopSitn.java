/*
 * Copyright (C) 2017 arx iT
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  SeeimportCommands the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.easysdi.extract.connectors.geoshop;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Map;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.easysdi.extract.connectors.common.IConnector;
import org.easysdi.extract.connectors.common.IConnectorImportResult;
import org.easysdi.extract.connectors.common.IExportRequest;
import org.easysdi.extract.connectors.geoshop.utils.RequestUtils;
import org.easysdi.extract.connectors.geoshop.utils.ZipUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 * A plugin that imports orders from an geoshop sitn server and exports their result.
 *
 * @author Florent Krin
 */
public class GeoshopSitn implements IConnector {

    /**
     * The path to the configuration of this plugin.
     */
    private static final String CONFIG_FILE_PATH = "connectors/geoshopsitn/properties/config.properties";

    /**
     * The status code returned to tell that an HTTP request resulted in the creation of a resource.
     */
    private static final int CREATED_HTTP_STATUS_CODE = 201;

    /**
     * The status code returned to tell that an HTTP request was accepted.
     */
    private static final int ACCEPTED_HTTP_STATUS_CODE = 202;

    /**
     * The status code returned to tell that an HTTP request has no content.
     */
    private static final int NO_CONTENT_HTTP_STATUS_CODE = 204;

    /**
     * The port that is used by default for HTTP requests.
     */
    private static final int DEFAULT_HTTP_PORT = 80;

    /**
     * The port that is used by default for secure HTTP requests.
     */
    private static final int DEFAULT_HTTPS_PORT = 443;

    /**
     * The status code returned to tell that an HTTP request succeeded.
     */
    private static final int SUCCESS_HTTP_STATUS_CODE = 200;

    /**
     * The writer to the application logs.
     */
    private final Logger logger = LoggerFactory.getLogger(GeoshopSitn.class);

    /**
     * The code that uniquely identifies this plugin.
     */
    private final String code = "geoshopextract";

    /**
     * The parameters values to communicate with a particular easySDI v4 server.
     */
    private Map<String, String> inputs;

    /**
     * The plugin configuration.
     */
    private ConnectorConfig config;

    /**
     * The messages to the user in the language used by the user interface.
     */
    private LocalizedMessages messages;



    /**
     * Creates a new easySDI v4 connector plugin instance with default parameters.
     */
    public GeoshopSitn() {
        this.config = new ConnectorConfig(GeoshopSitn.CONFIG_FILE_PATH);
        this.messages = new LocalizedMessages();
    }



    /**
     * Creates a new easySDI v4 connector plugin instance with default connection parameters.
     *
     * @param language the string that identifies the language used by the user interface
     */
    public GeoshopSitn(final String language) {
        this.config = new ConnectorConfig(GeoshopSitn.CONFIG_FILE_PATH);
        this.messages = new LocalizedMessages(language);
    }



    /**
     * Creates a new easySDI v4 connector plugin instance with the default user interface language.
     *
     * @param parametersValues the parameters values to connect to the easySDI v4 server
     */
    public GeoshopSitn(final Map<String, String> parametersValues) {
        this();
        this.inputs = parametersValues;
    }



    /**
     * Creates a new easySDI v4 connector plugin instance.
     *
     * @param language         the string that identifies the language used by the user interface
     * @param parametersValues the parameters values to connect to the easySDI v4 server
     */
    public GeoshopSitn(final String language, final Map<String, String> parametersValues) {
        this(language);
        this.inputs = parametersValues;
    }



    @Override
    public final GeoshopSitn newInstance(final String language) {
        return new GeoshopSitn(language);
    }



    @Override
    public final GeoshopSitn newInstance(final String language, final Map<String, String> parametersValues) {
        return new GeoshopSitn(language, parametersValues);
    }



    @Override
    public final String getLabel() {
        return this.messages.getString("plugin.label");
    }



    @Override
    public final String getCode() {
        return this.code;
    }



    @Override
    public final String getDescription() {
        return this.messages.getString("plugin.description");
    }



    @Override
    public final String getHelp() {
        return this.messages.getString("plugin.help");
    }



    @Override
    public final String getPicto() {
        return "";
    }



    @Override
    public final String getParams() {
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode parametersNode = mapper.createArrayNode();

        ObjectNode serviceUrlNode = parametersNode.addObject();
        serviceUrlNode.put("code", this.config.getProperty("code.serviceUrl"));
        serviceUrlNode.put("label", this.messages.getString("label.serviceUrl"));
        serviceUrlNode.put("type", "text");
        serviceUrlNode.put("req", true);
        serviceUrlNode.put("maxlength", 255);

        ObjectNode loginNode = parametersNode.addObject();
        loginNode.put("code", this.config.getProperty("code.login"));
        loginNode.put("label", this.messages.getString("label.login"));
        loginNode.put("type", "text");
        loginNode.put("req", true);
        loginNode.put("maxlength", 50);

        ObjectNode passwordNode = parametersNode.addObject();
        passwordNode.put("code", this.config.getProperty("code.password"));
        passwordNode.put("label", this.messages.getString("label.password"));
        passwordNode.put("type", "pass");
        passwordNode.put("req", true);
        passwordNode.put("maxlength", 50);

        ObjectNode uploadSizeNode = parametersNode.addObject();
        uploadSizeNode.put("code", this.config.getProperty("code.uploadSize"));
        uploadSizeNode.put("label", this.messages.getString("label.uploadSize"));
        uploadSizeNode.put("type", "numeric");
        uploadSizeNode.put("req", false);
        uploadSizeNode.put("min", 1);
        uploadSizeNode.put("step", 1);
        
        ObjectNode externalUrlPatternNode = parametersNode.addObject();
        externalUrlPatternNode.put("code", this.config.getProperty("code.detailsUrlPattern"));
        externalUrlPatternNode.put("label", this.messages.getString("label.detailsUrlPattern"));
        externalUrlPatternNode.put("type", "text");
        externalUrlPatternNode.put("req", false);
        externalUrlPatternNode.put("maxlength", 255);

        try {
            return mapper.writeValueAsString(parametersNode);

        } catch (JsonProcessingException exception) {
            logger.error("An error occurred when the parameters description array was converted to JSON.", exception);
            return null;
        }
    }



    /**
     * Obtains the message that explains the HTTP code return by an operation through this plugin.
     *
     * @param httpCode the returned HTTP code
     * @return the string that describe the HTTP status
     */
    private String getMessageFromHttpCode(final int httpCode) {
        final String genericErrorMessage = this.messages.getString("error.message.generic");
        final String httpErrorMessage = this.messages.getString(String.format("httperror.message.%d", httpCode));

        if (httpErrorMessage == null) {
            return genericErrorMessage;
        }

        return String.format("%s - %s", genericErrorMessage, httpErrorMessage);
    }



    @Override
    public final IConnectorImportResult importCommands() {
        this.logger.debug("Importing commands");

        ConnectorImportResult result;

        try {
            //call getOrder service
            this.logger.debug("Fetching orders from service");
            String tokenUrl = String.format("%s/%s", inputs.get(config.getProperty("code.serviceUrl")), config.getProperty("tokenEndPoint"));
            String targetUrl = String.format("%s/%s", inputs.get(config.getProperty("code.serviceUrl")), config.getProperty("getOrders.method"));
            result = this.callGetOrderService(
                    tokenUrl,
                    targetUrl,
                    inputs.get(config.getProperty("code.login")),
                    inputs.get(config.getProperty("code.password")));

        } catch (Exception exception) {
            this.logger.error("The import commands has failed", exception);
            result = new ConnectorImportResult();
            result.setStatus(false);
            result.setErrorMessage(String.format("%s : %s", this.messages.getString("importorder.exception"),
                    exception.getMessage()));
        }

        this.logger.info("output result : " + result.toString());
        return result;
    }



    @Override
    public final ExportResult exportResult(final IExportRequest request) {

        this.logger.debug("Exporting result orders (setProduct method)");

        ExportResult exportResult = null;

        File outputFile = null;

        try {

            if (!request.isRejected()) {
                outputFile = this.prepareOutputFileForRequest(request);

                if (outputFile == null) {
                    exportResult = new ExportResult();
                    exportResult.setSuccess(false);
                    exportResult.setResultCode("-1");
                    exportResult.setResultMessage(this.messages.getString("exportresult.prerequisite.error"));
                    exportResult.setErrorDetails(this.messages.getString("exportresult.prerequisite.nofile"));

                    return exportResult;
                }

                final int uploadLimit = NumberUtils.toInt(inputs.get(config.getProperty("code.uploadSize")));
                final long fileSizeInMB = FileUtils.sizeOf(outputFile) / FileUtils.ONE_MB;

                if (uploadLimit > 0 && fileSizeInMB > uploadLimit) {
                    final String detailsMessage = String.format(this.messages.getString("exportresult.upload.tooLarge"),
                            fileSizeInMB, uploadLimit);
                    exportResult = new ExportResult();
                    exportResult.setSuccess(false);
                    exportResult.setResultCode("-2");
                    exportResult.setResultMessage(this.messages.getString("exportresult.prerequisite.error"));
                    exportResult.setErrorDetails(detailsMessage);

                    return exportResult;
                }

                if (outputFile != null) {
                    final String outputFileName = outputFile.getName();
                    this.logger.debug("set filename {}", outputFileName);
                }
            }

            this.logger.debug("call setProduct");

            String tokenUrl = String.format("%s/%s", inputs.get(config.getProperty("code.serviceUrl")), config.getProperty("tokenEndPoint"));
            String exportUrl = String.format("%s/%s%s", inputs.get(config.getProperty("code.serviceUrl")), config.getProperty("setProduct.method"), request.getProductGuid());

            exportResult = this.callSetProductService(tokenUrl, exportUrl, inputs.get(config.getProperty("code.login")),
                    inputs.get(config.getProperty("code.password")), outputFile, request);

        } catch (Exception exception) {
            this.logger.error("The order export has failed.", exception);

            exportResult = new ExportResult();
            exportResult.setSuccess(false);
            exportResult.setResultCode("-1");
            exportResult.setResultMessage(String.format("%s: %s",
                    this.messages.getString("exportresult.executing.failed"), exception.getMessage()));
            exportResult.setErrorDetails(exception.getMessage());

        } finally {

            if (outputFile != null && outputFile.exists()) {
                this.logger.debug("Deleting output file…");

                if (!outputFile.delete()) {
                    this.logger.debug("Could not delete output file {}.", outputFile.getAbsolutePath());
                }
            }
        }

        return exportResult;
    }



    /**
     * Sends the document describing the result to export to the server.
     *
     * @param xmlDocument the XML document that contains the information about the processing result
     * @param url         the address where the document must be sent
     * @param login       the user name to authenticate with the server
     * @param password    the password to authenticate with the server
     * @param resultFile  the file generated by the processing
     * @return an export result object describing whether the export succeeded
     */
    private ExportResult callSetProductService(final String tokenUrl, final String url, final String login,
            final String password, final File resultFile, IExportRequest request) {

        try {
            final URI targetUri = new URI(url);
            final URI tokenUri = new URI(tokenUrl);
            final HttpHost targetServer = this.getHostFromUri(targetUri);

            return this.sendExportRequest(targetServer, tokenUri, targetUri, login, password, resultFile, request);

        } catch (Exception exc) {
            ExportResult exportResult = new ExportResult();
            exportResult.setSuccess(false);
            exportResult.setResultCode("-1");
            exportResult.setResultMessage(this.messages.getString("exportresult.executing.failed"));
            exportResult.setErrorDetails(exc.getMessage());
            this.logger.debug("The export orders has failed");

            return exportResult;
        }
    }



    /**
     * Sends the export data to the server.
     *
     * @param targetServer the host to send the data to
     * @param targetUri    the URL to send export data
     * @param login        the user name to authenticate with the server
     * @param password     the password to authenticate with the server
     * @param exportXml    the XML string that describes the result to export
     * @param resultFile   the file generated by the request processing
     * @return the file generated by the processing
     * @throws IOException                  the plugin could not communicate with the server
     */
    private ExportResult sendExportRequest(final HttpHost targetServer, final URI tokenUri, final URI targetUri, final String login,
            final String password, final File resultFile, IExportRequest request)
            throws IOException {

        String token = null;

        //Envoi de la requête pour récupérer le token
        try (final CloseableHttpClient client = HttpClients.createDefault()) {
            this.logger.debug("Executing authentication request.");
            token = getNewTokenIfCredentialsAreSpecified(client, tokenUri, login, password);
            this.logger.debug("token is " + token);
        }

        try (final CloseableHttpClient client = this.getHttpClient(targetServer, login, password)) {
            final HttpPut httpPut = this.createPutRequest(targetUri);
            httpPut.setHeader("Authorization", "Bearer " + token);
            MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
            entityBuilder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
            entityBuilder.setCharset(StandardCharsets.UTF_8);
            if (resultFile != null) {
                entityBuilder.addBinaryBody(this.messages.getString("api.param.file"), resultFile);
            }

            //Ajout des paramètres au body avant l'envoi de la requête
            entityBuilder.addTextBody(this.messages.getString("api.param.is_rejected"),
                    ObjectUtils.firstNonNull(String.valueOf(request.isRejected()), "false"));
            entityBuilder.addTextBody(this.messages.getString("api.param.comment"),
                    ObjectUtils.firstNonNull(request.getRemark(), ""),
                    ContentType.create("text/plain", Charset.forName("UTF-8")));
            entityBuilder.setContentType(ContentType.MULTIPART_FORM_DATA);

            HttpEntity multipart = entityBuilder.build();
            httpPut.setEntity(multipart);

            //Envoi de la requête vers l'API
            try (final CloseableHttpResponse response = client.execute(httpPut)) {
                final int statusCode = response.getStatusLine().getStatusCode();
                this.logger.info("The export request returned with the HTTP status {}.", statusCode);
                this.logger.debug("response = " + response);

                return this.parseExportResponse(response, request);
            }
        }

    }



    /**
     * Processes what the server sent back as a response to an export request.
     *
     * @param response the response from the server
     * @return the parsed result of the export
     * @throws IOException                  the response from the server could not be read
     */
    private ExportResult parseExportResponse(final HttpResponse response, final IExportRequest request)
            throws IOException {

        final int httpCode = response.getStatusLine().getStatusCode();
        final String httpMessage = this.getMessageFromHttpCode(httpCode);
        this.logger.debug("setProduct - HTTP request completed with status code {}.", httpCode);

        ExportResult exportResult = new ExportResult();
        String responseString = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        if (httpCode != GeoshopSitn.ACCEPTED_HTTP_STATUS_CODE && httpCode != GeoshopSitn.CREATED_HTTP_STATUS_CODE && httpCode != GeoshopSitn.SUCCESS_HTTP_STATUS_CODE) {
            this.logger.debug("setProduct has failed with HTTP code {} => return directly output", httpCode);
            exportResult.setSuccess(false);
            exportResult.setResultMessage(httpMessage);
            exportResult.setResultCode(String.valueOf(httpCode));
            exportResult.setErrorDetails(responseString);
            return exportResult;
        }

        this.logger.debug("HTTP request was successful. Response was {}.", responseString);
        exportResult.setSuccess(true);
        exportResult.setResultMessage(responseString);
        if (responseString.equals("") || responseString == null) {
            exportResult.setResultMessage(request.getRemark());
        }
        return exportResult;
    }



    /**
     * Builds an HTTP request to be sent with the GET method, adding proxy information if it is defined.
     *
     * @param url the address that the GET request must be sent to
     * @return the HTTP GET request object
     */
    private HttpGet createGetRequest(final URI url) {
        assert url != null : "The target url cannot be null.";

        this.logger.debug("Creating HTTP GET request for URL {}.", url);

        return (HttpGet) this.addProxyInfoToRequest(new HttpGet(url));
    }



    /**
     * Builds an HTTP request to be sent with the PUT method, with proxy information if it is defined.
     *
     * @param url the address that the PUT request must be sent to
     * @return the HTTP PUT request object
     */
    private HttpPut createPutRequest(final URI url) {
        assert url != null : "The target url cannot be null.";

        this.logger.debug("Creating HTTP GET request for URL {}.", url);

        return (HttpPut) this.addProxyInfoToRequest(new HttpPut(url));
    }



    /**
     * Adds information about the proxy server to use to communicate with the easySDI v4 server,
     * if appropriate.
     *
     * @param request the request to send to the easySDI v4 server
     * @return the request object with proxy information if appropriate
     */
    private HttpRequestBase addProxyInfoToRequest(final HttpRequestBase request) {
        assert request != null : "The request cannot be null.";

        final RequestConfig proxyConfig = this.getProxyConfiguration();

        if (proxyConfig != null) {
            this.logger.debug("Using the proxy server set in the system properties.");
            request.setConfig(proxyConfig);
        }

        return request;
    }



    /**
     * Obtains an object that contains authentication for the easySDI v4 server and, if appropriate, for
     * the proxy server.
     *
     * @param targetHost     the easySDI v4 server
     * @param targetLogin    the user name to authenticate with the easySDI v4 server
     * @param targetPassword the password to authenticate with the easySDI v4 server
     * @return the credentials provider object
     */
    private CredentialsProvider getCredentialsProvider(final HttpHost targetHost, final String targetLogin,
            final String targetPassword) {

        assert targetHost != null : "The target host cannot be null.";

        final CredentialsProvider credentials = new BasicCredentialsProvider();
        this.logger.debug("Setting credentials for the target server.");
        this.addCredentialsToProvider(credentials, targetHost, targetLogin, targetPassword);

        final HttpHost proxyHost = this.getProxyHost();

        if (proxyHost != null) {
            this.logger.debug("Setting credentials for the proxy server.");

            try {
                PropertiesConfiguration configuration = this.getApplicationConfiguration();
                final String proxyLogin = configuration.getString("http.proxyUser");
                final String proxyPassword = configuration.getString("http.proxyPassword");
                this.addCredentialsToProvider(credentials, proxyHost, proxyLogin, proxyPassword);

            } catch (ConfigurationException exception) {
                this.logger.error("Cannot read the application configuration. No proxy credentials set.", exception);
            }
        }

        return credentials;
    }



    /**
     * Obtains an object that holds the configuration of the easySDI v4 connector plugin.
     *
     * @return the configuration object
     * @throws ConfigurationException the configuration could not be parsed
     */
    private PropertiesConfiguration getApplicationConfiguration() throws ConfigurationException {
        return new PropertiesConfiguration("application.properties");
    }



    /**
     * Adds authentication information for a server to an existing credentials provider.
     *
     * @param provider the credentials provider to add the credentials to
     * @param host     the server to autenticate with
     * @param login    the user name to authenticate with the server
     * @param password the password to authenticate with the server
     * @return the credential provider with the added credentials
     */
    private CredentialsProvider addCredentialsToProvider(final CredentialsProvider provider, final HttpHost host,
            final String login, final String password) {
        assert host != null : "The host cannot be null.";

        if (!StringUtils.isEmpty(login) && password != null) {
            provider.setCredentials(new AuthScope(host), new UsernamePasswordCredentials(login, password));
            this.logger.debug("Credentials added for host {}:{}.", host.getHostName(), host.getPort());

        } else {
            this.logger.debug("No credentials set for host {}.", host.toHostString());
        }

        return provider;
    }



    /**
     * Obtains a client object to make authenticated HTTP requests.
     *
     * @param targetHost     the server to send the requests to
     * @param targetLogin    the user name to authenticate with the server
     * @param targetPassword the password to authenticate with the server
     * @return the HTTP client
     */
    private CloseableHttpClient getHttpClient(final HttpHost targetHost, final String targetLogin,
            final String targetPassword) {
        assert targetHost != null : "The target host cannot be null";

        final CredentialsProvider credentials = this.getCredentialsProvider(targetHost, targetLogin, targetPassword);

        return HttpClients.custom().setDefaultCredentialsProvider(credentials).build();
    }



    private String getNewTokenIfCredentialsAreSpecified(final CloseableHttpClient client, final URI targetUri, final String targetLogin,
            final String targetPassword) {

        HttpPost httpPost = new HttpPost(targetUri);
        String token = null;

        MultipartEntityBuilder builder = MultipartEntityBuilder.create();
        builder.addTextBody("username", targetLogin);
        builder.addTextBody("password", targetPassword);

        HttpEntity multipart = builder.build();
        httpPost.setEntity(multipart);

        try {
            CloseableHttpResponse response = client.execute(httpPost);

            String tokenResponse = webResponseToString(response);
            token = extractToken(tokenResponse, "access");

            client.close();
        } catch (Exception exc) {
            this.logger.error("Authentication has failed",
                    exc);
        }

        return token;
    }



    private String webResponseToString(CloseableHttpResponse response) throws IOException {

        Reader reader = new BufferedReader(new InputStreamReader(
                response.getEntity().getContent(), "UTF-8"));

        StringBuilder content = new StringBuilder();
        char[] buffer = new char[5000];
        int n;
        while ((n = reader.read(buffer)) != -1) {
            content.append(buffer, 0, n);
        }
        reader.close();
        return content.toString();
    }



    private String extractToken(String tokenResponse, String key) {
        String token = getJsonValue(tokenResponse, key);
        if (token == null || token.isEmpty()) {
            this.logger.warn("Token cannot be obtained: " + tokenResponse);
        } else {
            this.logger.info("Token obtained: " + token);
        }
        return token;
    }



    private String getJsonValue(String text, String key) {
        this.logger.debug("JSON Response: " + text);
        int i = text.indexOf(key);
        String value = "";
        if (i > -1) {
            value = text.substring(text.indexOf(':', i) + 1).trim();
            value = (value.length() > 0 && value.charAt(0) == '"')
                    ? value.substring(1, value.indexOf('"', 1))
                    : value.substring(0, Math.max(0, Math.min(Math.min(value.indexOf(","), value.indexOf("]")), value.indexOf("}"))));
        }
        this.logger.debug("Extracted Value: " + value);
        return value;
    }



    /**
     * Obtains the configuration of the proxy server to use to connect to the easySDI v4 server.
     *
     * @return the request configuration that uses the defined proxy, or <code>null</code> if no proxy is defined
     */
    private RequestConfig getProxyConfiguration() {
        final HttpHost proxy = this.getProxyHost();

        if (proxy == null) {
            return null;
        }

        return RequestConfig.custom().setProxy(proxy).build();
    }



    /**
     * Obtains the proxy server to use to connect to the easySDI v4 server, if any.
     *
     * @return the proxy server host, or <code>null</code> if no proxy is defined
     */
    private HttpHost getProxyHost() {

        try {
            PropertiesConfiguration applicationConfiguration = this.getApplicationConfiguration();
            final String proxyHostName = applicationConfiguration.getString("http.proxyHost");
            this.logger.debug("The proxy host set in the system properties is {}.", proxyHostName);

            if (proxyHostName == null) {
                this.logger.debug("No proxy set in the system properties.");
                return null;
            }

            final int proxyPort = applicationConfiguration.getInteger("http.proxyPort", -1);
            this.logger.debug("The proxy port in the system properties is {}.", proxyPort);

            return (proxyPort < 0) ? new HttpHost(proxyHostName) : new HttpHost(proxyHostName, proxyPort);

        } catch (ConfigurationException exception) {
            this.logger.error("Cannot read the application configuration. Proxy configuration (if any) ignored.",
                    exception);
            return null;
        }
    }



    /**
     * Sends the document requesting orders to process.
     *
     * @param url      the address to send the import request to
     * @param login    the user name to authenticate with the server
     * @param password the password to authenticate with the server
     * @return the result of the import
     * @throws Exception an error prevented the import to be completed
     */
    private ConnectorImportResult callGetOrderService(final String tokenUrl, final String url, final String login, final String password)
            throws Exception {
        this.logger.debug("Getting orders from service {}.", url);
        URI targetUri = new URI(url);
        URI tokenUri = new URI(tokenUrl);
        HttpHost targetServer = this.getHostFromUri(targetUri);

        return this.sendImportRequest(targetServer, tokenUri, targetUri, login, password);
    }



    /**
     * Obtains a host object based on an address.
     *
     * @param uri the address that contains the host information
     * @return the HTTP host for the server that the URL points to
     */
    private HttpHost getHostFromUri(final URI uri) {
        final String hostName = uri.getHost();
        int port = uri.getPort();
        final String scheme = uri.getScheme();

        if (port < 0) {

            switch (scheme.toLowerCase()) {

                case "http":
                    this.logger.debug("No port in URL for host {}. Using HTTP default 80.", hostName);
                    port = GeoshopSitn.DEFAULT_HTTP_PORT;
                    break;

                case "https":
                    this.logger.debug("No port in URL for host {}. Using HTTPS default 443.", hostName);
                    port = GeoshopSitn.DEFAULT_HTTPS_PORT;
                    break;

                default:
                    this.logger.error("Unsupported protocol {}.", scheme);
                    return null;
            }
        }

        return new HttpHost(hostName, port, scheme);
    }



    /**
     * Sends the import request data to the easySDI v4 server.
     *
     * @param targetServer the HTTP host that represents the easySDI v4 server
     * @param targetUri    the address to send the import request data to
     * @param login        the user name to authenticate with the server
     * @param password     the password to authenticate with the server
     * @return the result of the import
     * @throws IOException                  the plugin could not communicate with the server
     */
    private ConnectorImportResult sendImportRequest(final HttpHost targetServer, final URI tokenUri, final URI targetUri,
            final String login, final String password)
            throws IOException {

        String token = null;

        try (final CloseableHttpClient client = HttpClients.createDefault()) {
            this.logger.debug("Executing authentication request.");
            token = getNewTokenIfCredentialsAreSpecified(client, tokenUri, login, password);
            this.logger.debug("token is " + token);

        }

        try (final CloseableHttpClient client = HttpClients.createDefault()) {
            final HttpGet httpGet = this.createGetRequest(targetUri);
            httpGet.setHeader("Content-Type", "application/json");
            httpGet.setHeader("Authorization", "Bearer " + token);

            this.logger.debug("Executing order HTTP request.");

            try (final CloseableHttpResponse response = client.execute(httpGet)) {
                return this.parseImportResponse(response);
            }
        }
    }



    /**
     * Processes what the server returned as a response to an import request.
     *
     * @param response the response sent by the easySDI v4 server
     * @return the parsed import result
     * @throws IOException                  the response could not be read
     */
    private ConnectorImportResult parseImportResponse(final HttpResponse response)
            throws IOException {
        //verify the valid error code first
        final ConnectorImportResult result = new ConnectorImportResult();
        final int httpCode = response.getStatusLine().getStatusCode();
        final String httpMessage = this.getMessageFromHttpCode(httpCode);
        this.logger.debug("Order HTTP request completed with status code {}.", httpCode);

        if (httpCode != GeoshopSitn.CREATED_HTTP_STATUS_CODE
                && httpCode != GeoshopSitn.SUCCESS_HTTP_STATUS_CODE
                && httpCode != GeoshopSitn.NO_CONTENT_HTTP_STATUS_CODE) {
            this.logger.debug("getOrder has failed with HTTP code {} => return directly output", httpCode);
            result.setStatus(false);
            result.setErrorMessage(httpMessage);

            return result;
        } else if (httpCode == GeoshopSitn.NO_CONTENT_HTTP_STATUS_CODE) {
            this.logger.debug("getOrder was successfull but with no content and HTTP code {}", httpCode);
            result.setStatus(true);
            result.setErrorMessage(this.messages.getString(String.format("httperror.message.%d", httpCode)));
            return result;
        }

        this.logger.debug("HTTP request was successful. Response was {}.", response);

        final String responseString = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        if (!"".equals(responseString) && !"[]".equals(responseString)) {
            result.setStatus(true);

        } else {
            result.setStatus(false);
            result.setErrorMessage(this.messages.getString("importorders.result.xmlempty"));
        }

        this.logger.debug("Response content is:\n{}.", responseString);
        this.addImportedProductsToResult(responseString, result);

        return result;
    }



    /**
     * Adds a data item request to the collection of imported products.
     *
     * @param responseString the string that contains the import response from the server
     * @param result         the object that holds the processed result of the import request.
     * @return the import result object with the added product
     * @throws IOException                  the response could not be read
     */
    private ConnectorImportResult addImportedProductsToResult(final String responseString,
            final ConnectorImportResult result) throws IOException {

        this.logger.debug("Building document");
        final String detailsUrlPattern = this.inputs.get(this.config.getProperty("code.detailsUrlPattern"));

        JSONArray orderArray = new JSONArray(responseString);

        for (int i = 0; i < orderArray.length(); i++) {

            this.logger.debug("Processing order index {}.", i);
            JSONObject orderNode = orderArray.getJSONObject(i);
            final int orderId = orderNode.getInt("id");
            String orderLabel = String.valueOf(orderId) + " - " + orderNode.getString("title");
            String orderType = orderNode.getString("order_type");

            JSONObject client = orderNode.getJSONObject("client");
            String clientName = client.getString("first_name") + " " + client.getString("last_name");
            String clientOrganism = client.getString("company_name");
            int clientId = client.getInt("id");
            String clientAddress = client.getString("street") + ", " + client.getString("postcode") + " " + client.getString("city")
                + ", " + ObjectUtils.firstNonNull(client.getString("email"), client.getString("phone"));

            String tiersName = "";
            String tiersAddress = "";
            if (orderNode.isNull("invoice_contact") == false) {
                JSONObject tiers = orderNode.getJSONObject("invoice_contact");
                String tiersCompanyName = tiers.getString("company_name");
                tiersCompanyName = (tiersCompanyName == null || tiersCompanyName.isEmpty()) ? "" : " (" + tiersCompanyName + ")";
                tiersName = tiers.getString("first_name") + " " + tiers.getString("last_name");
                tiersAddress = tiers.getString("street") + ", " + tiers.getString("postcode") + " " + tiers.getString("city")
                    + tiersCompanyName + " " + ObjectUtils.firstNonNull(tiers.getString("email"), tiers.getString("phone"));
            }
            String detailsUrl;

            this.logger.debug("Parsing products.");
            JSONArray productsArray = orderNode.getJSONArray("items");
            for (int productIndex = 0; productIndex < productsArray.length(); productIndex++) {
                this.logger.debug("Processing product index {}.", productIndex);

                final Product product = new Product();

                final int productId = productsArray.getJSONObject(productIndex).getInt("id");
                this.logger.debug("Product GUID is {}.", productId);

                final JSONObject productNode = productsArray.getJSONObject(productIndex).getJSONObject("product");
                final String productLabel = productNode.getString("label");
                
                final String productOrganismGuid = productNode.getString("provider");
                final int catalogProductId = productNode.getInt("id");

                product.setOrderGuid(String.valueOf(orderId));
                product.setOrderLabel(orderLabel);
                product.setOrganismGuid(productOrganismGuid);
                product.setOrganism(clientOrganism);
                product.setClient(clientName);
                product.setClientGuid(String.valueOf(clientId));
                product.setClientDetails(StringUtils.strip(clientAddress, ", "));
                product.setTiers(tiersName.trim());
                product.setTiersDetails(StringUtils.strip(tiersAddress, ", "));
                product.setProductGuid(String.valueOf(productId));
                product.setProductLabel(productLabel);
                product.setOthersParameters(
                    "{\"data_format\" : \"" +
                    productsArray.getJSONObject(productIndex).getString("data_format") + "\",\n" +
                    "\"order_type\" : \"" + orderType + "\",\n" +
                    "\"product_id\" : " + String.valueOf(catalogProductId) + "}");
                product.setPerimeter(orderNode.getString("geom"));
                product.setSurface(orderNode.getDouble("geom_area"));
                
                this.logger.debug("Creating order details URL.");
                detailsUrl = null;

                if (detailsUrlPattern != null && detailsUrlPattern.length() > 0) {
                    this.logger.debug("Order details URL pattern is {}", detailsUrlPattern);
                    detailsUrl = RequestUtils.interpolateVariables(detailsUrlPattern, product, this.config);

                } else {
                    this.logger.debug("No order details URL pattern defined.");
                }
                
                product.setExternalUrl(detailsUrl);
                this.logger.debug("Details URL set to {}", detailsUrl);

                this.logger.debug("Adding product {} to result.", productId);
                result.addProduct(product);
            }

        }
        return result;
    }



    /**
     * Provides a name for a file to export as the result of an order process. The non-existence of a file with
     * this name in the folder is done when this method is executed, but it is of course not guaranteed that it will
     * still be available by the time the file is created.
     *
     * @param request        the order whose result must be exported
     * @param avoidCollision <code>true</code> to generate a name that will not match an existing file
     * @return the name for the file to export
     */
    private String getArchiveNameForRequest(final IExportRequest request, final boolean avoidCollision) {
        return this.getFileNameForRequest(request, "zip", avoidCollision);
    }



    /**
     * Provides a name for a file to export as the result of an order process. The non-existence of a file with
     * this name in the folder is done when this method is executed, but it is of course not guaranteed that it will
     * still be available by the time the file is created.
     *
     * @param request        the order whose result must be exported
     * @param extension      the string describing the type of the file, such as <code>pdf</code> or <code>zip</code>
     * @param avoidCollision <code>true</code> to generate a name that will not match an existing file
     * @return the name for the file to export
     */
    private String getFileNameForRequest(final IExportRequest request, final String extension,
            final boolean avoidCollision) {
        assert request != null : "The exported request cannot be null.";
        assert request.getOrderLabel() != null : "The label of the exported order cannot be null.";
        assert request.getProductLabel() != null : "The label of the exported product cannot be null.";

        final String baseFileName = String.format("%s_%s", request.getOrderGuid(), request.getProductLabel())
                .replaceAll("[\\s<>*\"/\\\\\\[\\]:;|=,]", "_");
        this.logger.debug("The raw base file name is {}", baseFileName);
        this.logger.debug("The bytes of the raw base file name is {}.", baseFileName.getBytes(StandardCharsets.UTF_8));
        final String sanitizedBaseFileName = StringUtils.stripAccents(baseFileName);
        final String fileName = String.format("%s.%s", sanitizedBaseFileName, extension);

        if (!avoidCollision) {
            return fileName;
        }

        int index = 1;
        final String folderOutPath = request.getFolderOut();
        File outputFile = new File(folderOutPath, fileName);

        while (outputFile.exists()) {
            outputFile = new File(folderOutPath, String.format("%s_%d.%s", sanitizedBaseFileName, index++, extension));
        }

        return outputFile.getName();
    }



    /**
     * Provides a file to export as the result of an order process.
     *
     * @param request the order whose result must be exported
     * @return the output file to export
     * @throws IOException if a file system error prevented the creation of the output file
     */
    private File prepareOutputFileForRequest(final IExportRequest request) throws IOException {
        assert request != null : "The request cannot be null.";
        assert StringUtils.isNotBlank(request.getFolderOut()) : "The request output folder path cannot be empty.";

        this.logger.debug("Getting result file");
        final String outputFolderPath = request.getFolderOut();
        final File outputFolder = new File(outputFolderPath);

        if (!outputFolder.exists() || !outputFolder.isDirectory()) {
            this.logger.error("Invalid or inaccessible output folder {}.", outputFolder.getCanonicalPath());
            return null;
        }

        Collection<File> outputFilesList = FileUtils.listFiles(outputFolder, null, true);

        if (outputFilesList.isEmpty()) {
            return null;
        }

        if (outputFilesList.size() == 1) {
            final File outputFolderFile = (File) outputFilesList.toArray()[0];
            final String outputFolderFileName = outputFolderFile.getName();
            final String extension = FilenameUtils.getExtension(outputFolderFileName);

            if (outputFolderFileName.equals(this.getFileNameForRequest(request, extension, false))) {
                this.logger.debug("Output folder only contains one file \"{}\" and it matches the desired"
                        + " result file name, so it will be sent as is.", outputFolderFileName);
                return outputFolderFile;
            }

            final String resultFileName = this.getFileNameForRequest(request, extension, true);

            this.logger.debug("Output folder only contains one file \"{}\", so this will be sent as the"
                    + " output file with the name \"{}\"", outputFolderFileName, resultFileName);
            return Files.copy(outputFolderFile.toPath(), Paths.get(outputFolderPath, resultFileName)).toFile();
        }
        return ZipUtils.zipFolderContentToFile(outputFolder, this.getArchiveNameForRequest(request, true));
    }
}
