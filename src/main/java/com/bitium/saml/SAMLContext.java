package com.bitium.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class SAMLContext {
	private static final Logger log = LoggerFactory.getLogger(SAMLContext.class);
	private static final SAMLProcessor samlProcessor;
	
	private MetadataManager metadataManager;
	private KeyManager idpKeyManager;
	
	private SAMLContextProviderImpl messageContextProvider;
	
	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			log.error("Error during DefaultBootstrap.bootstrap()", e);
		}
		
		SAMLBinding redirectBinding = new HTTPRedirectDeflateBinding(Configuration.getParserPool());
		SAMLBinding postBinding = new HTTPPostBinding(Configuration.getParserPool(), null);
        samlProcessor = new SAMLProcessorImpl(Arrays.asList(redirectBinding, postBinding));
	}

    public static String getIssuer(HttpServletRequest request) {
        String responseMessage = request.getParameter("SAMLResponse");
        byte[] base64DecodedResponse = Base64.decode(responseMessage);
        ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = null;
        try {
            docBuilder = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            log.error(e.getMessage(), e);
            return null;
        }

        Document document = null;
        try {
            document = docBuilder.parse(is);
        } catch (SAXException | IOException e) {
            log.error(e.getMessage(), e);
            return null;
        }
        Element element = document.getDocumentElement();

        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        XMLObject responseXmlObj = null;
        try {
            responseXmlObj = unmarshaller.unmarshall(element);
        } catch (UnmarshallingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
        Response response = (Response) responseXmlObj;
        return response.getIssuer().getValue();
    }

	public SAMLContext(HttpServletRequest request, SAMLConfig configuration) throws ConfigurationException, CertificateException, UnsupportedEncodingException, MetadataProviderException, ServletException, ResourceException {
		configuration.setDefaultBaseUrl(getDefaultBaseURL(request));
		
		idpKeyManager = new IdpKeyManager(configuration.getIdpEntityId(), configuration.getX509Certificate());
		SpMetadataGenerator spMetadataGenerator = new SpMetadataGenerator();
		MetadataProvider spMetadataProvider = spMetadataGenerator.generate(configuration);
		IdpMetadataGenerator idpMetadataGenerator = new IdpMetadataGenerator();
		MetadataProvider idpMetadataProvider = idpMetadataGenerator.generate(configuration);
		
		metadataManager = new MetadataManager(Arrays.asList(spMetadataProvider, idpMetadataProvider));
		metadataManager.setKeyManager(idpKeyManager);
		metadataManager.setHostedSPName(configuration.getSpEntityId());
		metadataManager.refreshMetadata();
		
		messageContextProvider = new SAMLContextProviderImpl();
		messageContextProvider.setMetadata(metadataManager);
		messageContextProvider.setKeyManager(idpKeyManager);
		messageContextProvider.afterPropertiesSet();
	}
	
	public SAMLMessageContext createSamlMessageContext(HttpServletRequest request, HttpServletResponse response) throws ServletException, MetadataProviderException {
		SAMLMessageContext context = messageContextProvider.getLocalAndPeerEntity(request, response);
		
		SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
		
		String responseURL = request.getRequestURL().toString();
		spDescriptor.getDefaultAssertionConsumerService().setResponseLocation(responseURL);
		for (AssertionConsumerService service : spDescriptor.getAssertionConsumerServices()) {
			service.setResponseLocation(responseURL);
		}
		
		spDescriptor.setAuthnRequestsSigned(false);
		context.setCommunicationProfileId(SAMLConstants.SAML2_WEBSSO_PROFILE_URI);
		
		return context;
	}

	public SAMLProcessor getSamlProcessor() {
		return samlProcessor;
	}

	public MetadataManager getMetadataManager() {
		return metadataManager;
	}
	
	public KeyManager getIdpKeyManager() {
		return idpKeyManager;
	}

	private String getDefaultBaseURL(HttpServletRequest request) {
        StringBuilder sb = new StringBuilder();
        sb.append(request.getScheme()).append("://").append(request.getServerName()).append(":").append(request.getServerPort());
        sb.append(request.getContextPath());
        return sb.toString();
    }
	
	
}
