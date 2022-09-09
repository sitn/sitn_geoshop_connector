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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.easysdi.extract.connectors.geoshop;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.easysdi.extract.connectors.common.IConnectorImportResult;
import org.easysdi.extract.connectors.common.IExportResult;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 *
 * @author Yves Grasset
 */
public class GeoshopSitnTest {
    private static final String CONFIG_FILE_PATH = "connectors/geoshopsitn/properties/config.properties";
    private static final String DESCRIPTION_STRING_IDENTIFIER = "plugin.description";
    private static final String EXPECTED_ICON_CLASS = "";
    private static final String EXPECTED_PLUGIN_CODE = "geoshopextract";
    private static final String DETAILS_URL_PARAMETER_NAME_PROPERTY = "code.detailsUrlPattern";
    private static final String HELP_STRING_IDENTIFIER = "plugin.help";
    private static final String INSTANCE_LANGUAGE = "fr";
    private static final String LABEL_STRING_IDENTIFIER = "plugin.label";
    private static final String LOGIN_PARAMETER_NAME_PROPERTY = "code.login";
    private static final String PARAMETER_CODE_NAME = "code";
    private static final String PARAMETER_LABEL_NAME = "label";
    private static final String PARAMETER_MAX_LENGTH_NAME = "maxlength";
    private static final String PARAMETER_MAX_VALUE_NAME = "max";
    private static final String PARAMETER_MIN_VALUE_NAME = "min";
    private static final String PARAMETER_REQUIRED_NAME = "req";
    private static final String PARAMETER_STEP_NAME = "step";
    private static final String PARAMETER_TYPE_NAME = "type";
    private static final String PASSWORD_PARAMETER_NAME_PROPERTY = "code.password";
    private static final String TEST_BASE_PATH = "/var/extract/orders";
    private static final String TEST_LOGIN = "extract";
    private static final String TEST_PASSWORD = "Arxit200";
    private static final String TEST_UPLOAD_SIZE = "1024";
    private static final String TEST_URL = "https://sitn.ne.ch/geoshop2_prepub_api";
    private static final String TEST_DETAILS_URL = "https://sitn.ne.ch/geoshop2_prepub_api/admin/api/order/20118/change/";
    private static final String UPLOAD_SIZE_PARAMETER_NAME_PROPERTY = "code.uploadSize";
    private static final String URL_PARAMETER_NAME_PROPERTY = "code.serviceUrl";
    private static final String[] VALID_PARAMETER_TYPES = new String[]{"email", "pass", "multitext", "text", "numeric"};

    /**
     * The writer to the application logs.
     */
    private final Logger logger = LoggerFactory.getLogger(GeoshopSitnTest.class);

    private ConnectorConfig configuration;
    private LocalizedMessages messages;
    private ObjectMapper parameterMapper;
    private String[] requiredParametersCodes;
    private Map<String, String> testParameters;



    public GeoshopSitnTest() {
    }



    @BeforeClass
    public static final void setUpClass() {

    }



    @AfterClass
    public static final void tearDownClass() {
    }



    @Before
    public final void setUp() {
        this.configuration = new ConnectorConfig(GeoshopSitnTest.CONFIG_FILE_PATH);
        this.messages = new LocalizedMessages(GeoshopSitnTest.INSTANCE_LANGUAGE);

        final String loginCode = this.configuration.getProperty(GeoshopSitnTest.LOGIN_PARAMETER_NAME_PROPERTY);
        final String passwordCode = this.configuration.getProperty(GeoshopSitnTest.PASSWORD_PARAMETER_NAME_PROPERTY);
        final String urlCode = this.configuration.getProperty(GeoshopSitnTest.URL_PARAMETER_NAME_PROPERTY);
        final String uploadSizeCode = this.configuration.getProperty(GeoshopSitnTest.UPLOAD_SIZE_PARAMETER_NAME_PROPERTY);
        final String detailsUrlPattern
        	= this.configuration.getProperty(GeoshopSitnTest.DETAILS_URL_PARAMETER_NAME_PROPERTY);

        this.requiredParametersCodes = new String[]{loginCode, passwordCode, urlCode, uploadSizeCode, detailsUrlPattern};

        this.testParameters = new HashMap<>();
        this.testParameters.put(loginCode, GeoshopSitnTest.TEST_LOGIN);
        this.testParameters.put(passwordCode, GeoshopSitnTest.TEST_PASSWORD);
        this.testParameters.put(urlCode, GeoshopSitnTest.TEST_URL);
        this.testParameters.put(uploadSizeCode, GeoshopSitnTest.TEST_UPLOAD_SIZE);
        this.testParameters.put(detailsUrlPattern, GeoshopSitnTest.TEST_DETAILS_URL);

        this.parameterMapper = new ObjectMapper();
    }



    @After
    public final void tearDown() {
    }



    /**
     * Test of newInstance method, of class GeoshopSitnTest.
     */
    @Test
    public final void testNewInstanceWithoutParameters() {
        System.out.println("newInstance without parameters");
        GeoshopSitn instance = new GeoshopSitn();
        GeoshopSitn result = instance.newInstance(GeoshopSitnTest.INSTANCE_LANGUAGE);
        Assert.assertNotSame(instance, result);
    }



    /**
     * Test of newInstance method, of class GeoshopSitn.
     */
    @Test
    public final void testNewInstanceWithParameters() {
        System.out.println("newInstance with parameters");
        GeoshopSitn instance = new GeoshopSitn();
        GeoshopSitn result = instance.newInstance(GeoshopSitnTest.INSTANCE_LANGUAGE, this.testParameters);

        System.out.println("import Commands");

    }



    /**
     * Test of getLabel method, of class GeoshopSitn.
     */
    @Test
    public final void testGetLabel() {
        System.out.println("getLabel");
        GeoshopSitn instance = new GeoshopSitn(GeoshopSitnTest.INSTANCE_LANGUAGE);
        String expResult = this.messages.getString(GeoshopSitnTest.LABEL_STRING_IDENTIFIER);
        String result = instance.getLabel();
        Assert.assertEquals(expResult, result);
    }



    /**
     * Test of getCode method, of class GeoshopSitn.
     */
    @Test
    public final void testGetCode() {
        System.out.println("getCode");
        GeoshopSitn instance = new GeoshopSitn();
        String result = instance.getCode();
        Assert.assertEquals(GeoshopSitnTest.EXPECTED_PLUGIN_CODE, result);
    }



    /**
     * Test of getDescription method, of class GeoshopSitn.
     */
    @Test
    public final void testGetDescription() {
        System.out.println("getDescription");
        GeoshopSitn instance = new GeoshopSitn(GeoshopSitnTest.INSTANCE_LANGUAGE);
        String expResult = this.messages.getString(GeoshopSitnTest.DESCRIPTION_STRING_IDENTIFIER);
        String result = instance.getDescription();
        Assert.assertEquals(expResult, result);
    }



    /**
     * Test of getHelp method, of class GeoshopSitn.
     */
    @Test
    public final void testGetHelp() {
        System.out.println("getHelp");
        GeoshopSitn instance = new GeoshopSitn(GeoshopSitnTest.INSTANCE_LANGUAGE);
        String expResult = this.messages.getString(GeoshopSitnTest.HELP_STRING_IDENTIFIER);
        String result = instance.getHelp();
        Assert.assertEquals(expResult, result);
    }



    /**
     * Test of getPicto method, of class GeoshopSitn.
     */
    @Test
    public final void testGetPicto() {
        System.out.println("getPicto");
        GeoshopSitn instance = new GeoshopSitn();
        String result = instance.getPicto();
        Assert.assertEquals(GeoshopSitnTest.EXPECTED_ICON_CLASS, result);
    }



    /**
     * Test of getParams method, of class GeoshopSitn.
     */
    @Test
    public final void testGetParams() {
        System.out.println("getParams");
        GeoshopSitn instance = new GeoshopSitn();
        ArrayNode parametersArray = null;

        try {
            parametersArray = this.parameterMapper.readValue(instance.getParams(), ArrayNode.class);

        } catch (IOException exception) {
            this.logger.error("An error occurred when the parameters JSON was parsed.", exception);
            Assert.fail("Could not parse the parameters JSON string.");
        }

        Assert.assertNotNull(parametersArray);
        Assert.assertEquals(this.testParameters.size(), parametersArray.size());
        List<String> requiredCodes = new ArrayList<>(Arrays.asList(requiredParametersCodes));

        for (int parameterIndex = 0; parameterIndex < parametersArray.size(); parameterIndex++) {
            JsonNode parameterData = parametersArray.get(parameterIndex);
            Assert.assertTrue(String.format("The parameter #%d does not have a code property", parameterIndex),
                    parameterData.hasNonNull(GeoshopSitnTest.PARAMETER_CODE_NAME));
            String parameterCode = parameterData.get(GeoshopSitnTest.PARAMETER_CODE_NAME).textValue();
            Assert.assertTrue(String.format("The code for parameter #%d is null or blank", parameterIndex),
                    StringUtils.isNotBlank(parameterCode));
            Assert.assertTrue(
                    String.format("The parameter code %s is not expected or has already been defined.", parameterCode),
                    requiredCodes.indexOf(parameterCode) >= 0
            );
            requiredCodes.remove(parameterCode);

            Assert.assertTrue(String.format("The parameter %s does not have a label property", parameterCode),
                    parameterData.hasNonNull(GeoshopSitnTest.PARAMETER_LABEL_NAME));
            String label = parameterData.get(GeoshopSitnTest.PARAMETER_LABEL_NAME).textValue();
            Assert.assertTrue(String.format("The label for parameter %s is null or blank.", parameterCode),
                    StringUtils.isNotBlank(label));

            Assert.assertTrue(String.format("The parameter %s does not have a type property", parameterCode),
                    parameterData.hasNonNull(GeoshopSitnTest.PARAMETER_TYPE_NAME));
            String parameterType = parameterData.get(GeoshopSitnTest.PARAMETER_TYPE_NAME).textValue();
            Assert.assertTrue(String.format("The type for parameter %s is invalid.", parameterCode),
                    StringUtils.isNotBlank(label)
                    && ArrayUtils.contains(GeoshopSitnTest.VALID_PARAMETER_TYPES, parameterType));

            Assert.assertTrue(String.format("The parameter %s does not have a required property", parameterCode),
                    parameterData.hasNonNull(GeoshopSitnTest.PARAMETER_REQUIRED_NAME));
            Assert.assertTrue(String.format("The required field for the parameter %s is not a boolean", parameterCode),
                    parameterData.get(GeoshopSitnTest.PARAMETER_REQUIRED_NAME).isBoolean());

            if (parameterType.equals("numeric")) {
                Integer maxValue = null;

                if (parameterData.hasNonNull(GeoshopSitnTest.PARAMETER_MAX_VALUE_NAME)) {
                    Assert.assertTrue(String.format("The maximum value for parameter %s is not a number",
                            parameterCode), parameterData.get(GeoshopSitnTest.PARAMETER_MAX_VALUE_NAME).isNumber());
                    maxValue = parameterData.get(GeoshopSitnTest.PARAMETER_MAX_VALUE_NAME).intValue();
                }

                if (parameterData.hasNonNull(GeoshopSitnTest.PARAMETER_MIN_VALUE_NAME)) {
                    Assert.assertTrue(String.format("The minimum value for parameter %s is not an integer",
                            parameterCode), parameterData.get(GeoshopSitnTest.PARAMETER_MIN_VALUE_NAME).isInt());
                    int minValue = parameterData.get(GeoshopSitnTest.PARAMETER_MIN_VALUE_NAME).intValue();

                    if (maxValue != null) {
                        Assert.assertTrue(
                                String.format("The minimum value for parameter %s must be less than the maximum value",
                                        parameterCode), minValue < maxValue);
                    }
                }

                if (parameterData.hasNonNull(GeoshopSitnTest.PARAMETER_STEP_NAME)) {
                    Assert.assertTrue(String.format("The step value for parameter %s is not an integer", parameterCode),
                            parameterData.get(GeoshopSitnTest.PARAMETER_STEP_NAME).isInt());
                }

            } else {
                Assert.assertTrue(String.format("The parameter %s does not have a maximum length property", parameterCode),
                        parameterData.hasNonNull(GeoshopSitnTest.PARAMETER_MAX_LENGTH_NAME));
                Assert.assertTrue(String.format("The maximum length for parameter %s is not an integer", parameterCode),
                        parameterData.get(GeoshopSitnTest.PARAMETER_MAX_LENGTH_NAME).isInt());
                int maxLength = parameterData.get(GeoshopSitnTest.PARAMETER_MAX_LENGTH_NAME).intValue();
                Assert.assertTrue(
                        String.format("The maximum length of parameter %s is not strictly positive", parameterCode),
                        maxLength > 0
                );
            }
        }

        Assert.assertTrue(
                String.format("The following parameters are missing: %s", StringUtils.join(requiredCodes, ", ")),
                requiredCodes.isEmpty()
        );
    }



    /**
     * Test of importCommands method, of class GeoshopSitn.
     */
    @Test
    public final void testImportCommands() {

        System.out.println("newInstance with parameters");
        GeoshopSitn instance = new GeoshopSitn();
        GeoshopSitn pluginInstance = instance.newInstance(GeoshopSitnTest.INSTANCE_LANGUAGE, this.testParameters);
        IConnectorImportResult result;

        /*result = pluginInstance.importCommands();
        if (result == null) {
            Assert.fail("The commands import for connector returned a null result.");
            return;
        }

        if (!result.getStatus()) {
            Assert.fail("The commands import for connector failed.");
            return;
        }*/
    }



    /**
     * Test of exportResult method, of class GeoshopSitn.
     */
    @Test
    public final void testExportResult() {

        GeoshopSitn instance = new GeoshopSitn();
        GeoshopSitn pluginInstance = instance.newInstance(GeoshopSitnTest.INSTANCE_LANGUAGE, this.testParameters);
        ExportRequest request = new ExportRequest();
        //Données bouchons
        request.setClient("Jean Michoud");
        request.setClientGuid("1373");
        request.setFolderIn("/var/extract/orders/34495/input");
        request.setFolderOut("/var/extract/orders/34495/output");
        request.setOrderGuid("11971");
        request.setOrderLabel("Plan de situation pour enquête");
        request.setProductGuid("34543");
        request.setProductLabel("MO - Cadastre complet");
        request.setTiers("Marcelle Rieda");
        request.setStatus("FINISHED");
        request.setRejected(true);
        request.setRemark("Voilà commande rejetée");

        IExportResult result = pluginInstance.exportResult(request);
    }

}
