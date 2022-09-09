import ch.asit_asso.extract.connectors.common.IConnector;
import ch.asit_asso.extract.connectors.geoshop.GeoshopSitn;

module ch.asit_asso.extract.connectors.geoshop {
    provides IConnector
            with GeoshopSitn;

    requires ch.asit_asso.extract.commonInterface;

    requires com.fasterxml.jackson.core;
    requires com.fasterxml.jackson.databind;
    requires commons.configuration;
    requires java.xml;
    requires org.apache.commons.io;
    requires org.apache.commons.lang3;
    requires org.apache.httpcomponents.httpclient;
    requires org.apache.httpcomponents.httpcore;
    requires org.apache.httpcomponents.httpmime;
    requires org.slf4j;
    requires logback.classic;
	requires json;
}