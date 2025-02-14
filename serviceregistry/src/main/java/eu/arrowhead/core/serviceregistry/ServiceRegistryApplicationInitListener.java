/********************************************************************************
 * Copyright (c) 2019 AITIA
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *   AITIA - implementation
 *   Arrowhead Consortia - conceptualization
 ********************************************************************************/

package eu.arrowhead.core.serviceregistry;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import ai.aitia.arrowhead.application.library.ArrowheadService;
import ai.aitia.arrowhead.application.library.util.ApplicationCommonConstants;
import eu.arrowhead.application.skeleton.provider.security.ProviderSecurityConfig;
import eu.arrowhead.application.skeleton.publisher.event.PresetEventType;
import eu.arrowhead.common.ApplicationInitListener;
import eu.arrowhead.common.CommonConstants;
import eu.arrowhead.common.CoreDefaults;
import eu.arrowhead.common.Utilities;
import eu.arrowhead.common.core.CoreSystem;
import eu.arrowhead.common.core.CoreSystemService;
import eu.arrowhead.common.database.entity.System;
import eu.arrowhead.common.database.service.CommonDBService;
import eu.arrowhead.common.dto.shared.EventPublishRequestDTO;
import eu.arrowhead.common.dto.shared.ServiceRegistryRequestDTO;
import eu.arrowhead.common.dto.shared.ServiceSecurityType;
import eu.arrowhead.common.dto.shared.SystemRequestDTO;
import eu.arrowhead.common.exception.ArrowheadException;
import eu.arrowhead.common.exception.DataNotFoundException;
import eu.arrowhead.core.serviceregistry.database.service.ServiceRegistryDBService;
import io.swagger.models.HttpMethod;

@Component
public class ServiceRegistryApplicationInitListener extends ApplicationInitListener {

    //=================================================================================================
    // members

    @Autowired
    private CommonDBService commonDBService;

    @Autowired
    private ServiceRegistryDBService serviceRegistryDBService;

    @Autowired
	private ArrowheadService arrowheadService;
	
	@Autowired
	private ProviderSecurityConfig providerSecurityConfig;
	
	@Value(ApplicationCommonConstants.$TOKEN_SECURITY_FILTER_ENABLED_WD)
	private boolean tokenSecurityFilterEnabled;
	
	@Value(CommonConstants.$SERVER_SSL_ENABLED_WD)
	private boolean sslEnabled;
	
	@Value(ApplicationCommonConstants.$APPLICATION_SYSTEM_NAME)
	private String mySystemName;
	
	@Value(ApplicationCommonConstants.$APPLICATION_SERVER_ADDRESS_WD)
	private String mySystemAddress;
	
	@Value(ApplicationCommonConstants.$APPLICATION_SERVER_PORT_WD)
	private int mySystemPort;

    //=================================================================================================
    // assistant methods

    //-------------------------------------------------------------------------------------------------
    @Override
    protected void customInit(final ContextRefreshedEvent event) {
        logger.debug("customInit started...");
        if (!isOwnCloudRegistered()) {
            registerOwnCloud(event.getApplicationContext());
        }

        try {
            final String name = coreSystemRegistrationProperties.getCoreSystem().name().toLowerCase();
            final List<System> oldSystems = serviceRegistryDBService.getSystemByName(name);
            if (!oldSystems.isEmpty()) {
                for (final System system : oldSystems) {
                    removeServiceRegistryEntries(system);
                    serviceRegistryDBService.removeSystemById(system.getId());
                }
            }

            final String authInfo = sslProperties.isSslEnabled() ? Base64.getEncoder().encodeToString(publicKey.getEncoded()) : null;
            final SystemRequestDTO systemRequestDTO = new SystemRequestDTO(name, coreSystemRegistrationProperties.getCoreSystemDomainName(),
                                                                           coreSystemRegistrationProperties.getCoreSystemDomainPort(), authInfo, null);

            final ServiceSecurityType securityType = sslProperties.isSslEnabled() ? ServiceSecurityType.CERTIFICATE : ServiceSecurityType.NOT_SECURE;
            final String serviceInterface = sslProperties.isSslEnabled() ? CommonConstants.HTTP_SECURE_JSON : CommonConstants.HTTP_INSECURE_JSON;

            for (final CoreSystemService service : CoreSystem.SERVICEREGISTRY.getServices()) {
                final ServiceRegistryRequestDTO registryRequest = new ServiceRegistryRequestDTO();
                registryRequest.setProviderSystem(systemRequestDTO);
                registryRequest.setServiceDefinition(service.getServiceDefinition());
                registryRequest.setInterfaces(List.of(serviceInterface));
                registryRequest.setServiceUri(service.getServiceUri());
                registryRequest.setSecure(securityType.name());

                serviceRegistryDBService.registerServiceResponse(registryRequest);
            }
        } catch (final ArrowheadException ex) {
            logger.error("Can't registrate {} as a system.", coreSystemRegistrationProperties.getCoreSystem().name());
            logger.debug("Stacktrace", ex);
        }
        
        try {
        	serviceRegistryDBService.calculateSystemAddressTypeIfNecessary();
        } catch (final ArrowheadException ex) {
        	logger.warn("Problem occurs during calculating system address types: {}", ex.getMessage());
        	logger.debug("Stacktrace", ex);
        }
    }

    // Method to show menu and handle user input
	private void showMenu() throws CertificateException {
        Scanner scanner = new Scanner(java.lang.System.in);
		while (true) {
			java.lang.System.out.println("Select an option:");
			java.lang.System.out.println("1. View assets");
			java.lang.System.out.println("2. Create new asset");
			java.lang.System.out.println("3. Exit");

			int choice = scanner.nextInt();
			scanner.nextLine(); // Consume newline

			switch (choice) {
				case 1:
					// Logic to view assets
					java.lang.System.out.println("Viewing assets...");
					viewAssets();
					break;
				case 2:
					// Logic to create new asset
					java.lang.System.out.println("Enter asset name:\n");
					String name = scanner.nextLine();
					java.lang.System.out.println("Enter asset endpoint:\n");
					String endpoint = scanner.nextLine();
					publishMyEvent(name, endpoint);
					break;
                case 3:
					java.lang.System.out.println("Starting Event Handler configuration");
					//Checking the availability of necessary core systems
					checkCoreSystemReachability(CoreSystem.SERVICEREGISTRY);
					if (sslEnabled && tokenSecurityFilterEnabled) {
						checkCoreSystemReachability(CoreSystem.AUTHORIZATION);			

						//Initialize Arrowhead Context
						arrowheadService.updateCoreServiceURIs(CoreSystem.AUTHORIZATION);
						
						setTokenSecurityFilter();
					} else {
						logger.info("TokenSecurityFilter in not active");
					}		
					
					//Register services into ServiceRegistry
					final ServiceRegistryRequestDTO createCarServiceRequest = createServiceRegistryRequest(SystemProviderWithPublishingConstants.CREATE_SYSTEM_SERVICE_DEFINITION, SystemProviderWithPublishingConstants.SYSTEM_URI, HttpMethod.POST);		
					arrowheadService.forceRegisterServiceToServiceRegistry(createCarServiceRequest);
					
					final ServiceRegistryRequestDTO getCarServiceRequest = createServiceRegistryRequest(SystemProviderWithPublishingConstants.GET_SYSTEM_SERVICE_DEFINITION,  SystemProviderWithPublishingConstants.SYSTEM_URI, HttpMethod.GET);
					getCarServiceRequest.getMetadata().put(SystemProviderWithPublishingConstants.REQUEST_PARAM_KEY_NAME, SystemProviderWithPublishingConstants.REQUEST_PARAM_NAME);
					getCarServiceRequest.getMetadata().put(SystemProviderWithPublishingConstants.REQUEST_PARAM_KEY_ENDPOINT, SystemProviderWithPublishingConstants.REQUEST_PARAM_ENDPOINT);
					arrowheadService.forceRegisterServiceToServiceRegistry(getCarServiceRequest);
					
					if (arrowheadService.echoCoreSystem(CoreSystem.EVENTHANDLER)) {
						arrowheadService.updateCoreServiceURIs(CoreSystem.EVENTHANDLER);	
					}
					return;
				case 4:
					java.lang.System.out.println("Exiting...");
					scanner.close();
					customDestroy();
					return;
				default:
                    java.lang.System.out.println("Invalid choice. Please try again.");
			}
		}
	}

	// Method to view assets
	private void viewAssets() {
		HttpClient client = HttpClient.newHttpClient();
		HttpRequest request = HttpRequest.newBuilder()
			.uri(URI.create("http://localhost:8082/registry/api/v1/registry"))
			.GET()
			.build();

		client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
			.thenApply(HttpResponse::body)
			.thenAccept(this::parseAndDisplayAssets)
			.join();
	}

	// Method to parse and display assets
	private void parseAndDisplayAssets(String responseBody) {
		JSONArray assets = new JSONArray(responseBody);
		for (int i = 0; i < assets.length(); i++) {
			JSONObject asset = assets.getJSONObject(i);
			String idShort = asset.getString("idShort");
			String id = asset.getJSONObject("identification").getString("id");
			String endpoint = asset.getJSONArray("endpoints").getJSONObject(0).getString("address");

			java.lang.System.out.println("Asset ID Short: " + idShort);
			java.lang.System.out.println("Asset ID: " + id);
			java.lang.System.out.println("Endpoint: " + endpoint);
			java.lang.System.out.println("-------------------------");
		}
	}

    //-------------------------------------------------------------------------------------------------
    private void removeServiceRegistryEntries(final System system) {
        for (final CoreSystemService service : CoreSystem.SERVICEREGISTRY.getServices()) {
        	try {
				serviceRegistryDBService.removeServiceRegistry(service.getServiceDefinition(), system.getSystemName(), system.getAddress(), system.getPort(), service.getServiceUri());
			} catch (final Exception ex) {
        		// ignore
			}
        }
    }

    //-------------------------------------------------------------------------------------------------
    private boolean isOwnCloudRegistered() {
        logger.debug("isOwnCloudRegistered started...");
        try {
            commonDBService.getOwnCloud(sslProperties.isSslEnabled());
            return true;
        } catch (final DataNotFoundException ex) {
            return false;
        }
    }

    //-------------------------------------------------------------------------------------------------
    private void registerOwnCloud(final ApplicationContext appContext) {
        logger.debug("registerOwnCloud started...");

        if (!standaloneMode) {
            String name = CoreDefaults.DEFAULT_OWN_CLOUD_NAME;
            String operator = CoreDefaults.DEFAULT_OWN_CLOUD_OPERATOR;

            if (sslProperties.isSslEnabled()) {
                @SuppressWarnings("unchecked") final Map<String, Object> context = appContext.getBean(CommonConstants.ARROWHEAD_CONTEXT, Map.class);
                final String serverCN = (String) context.get(CommonConstants.SERVER_COMMON_NAME);
                final String[] serverFields = serverCN.split("\\.");
                name = serverFields[1];
                operator = serverFields[2];
            }

            commonDBService.insertOwnCloud(operator, name, sslProperties.isSslEnabled(), null);
            logger.info("{}.{} own cloud is registered in {} mode.", name, operator, getModeString());
        }
    }
    //=================================================================================================
	// assistant methods

	//-------------------------------------------------------------------------------------------------
	private void publishMyEvent(String name, String endpoint) {
		final String eventType = PresetEventType.MY_CUSTOM_EVENT.getEventTypeName();
		
		final SystemRequestDTO source = new SystemRequestDTO();
		source.setSystemName(mySystemName);
		source.setAddress(mySystemAddress);
		source.setPort(mySystemPort);
		if (sslEnabled) {
			source.setAuthenticationInfo(Base64.getEncoder().encodeToString( arrowheadService.getMyPublicKey().getEncoded()));
		}

		final Map<String,String> metadata = null;
		final String payload = name + "/" + endpoint;
		final String timeStamp = Utilities.convertZonedDateTimeToUTCString( ZonedDateTime.now() );
		
		final EventPublishRequestDTO publishRequestDTO = new EventPublishRequestDTO(
				eventType, 
				source, 
				metadata, 
				payload, 
				timeStamp);
		
		arrowheadService.publishToEventHandler(publishRequestDTO);
	}

	//-------------------------------------------------------------------------------------------------
	private void setTokenSecurityFilter() throws CertificateException {
		final PublicKey authorizationPublicKey = arrowheadService.queryAuthorizationPublicKey();
		if (authorizationPublicKey == null) {
			throw new ArrowheadException("Authorization public key is null");
		}
		
		KeyStore keystore;
		try {
			keystore = KeyStore.getInstance(sslProperties.getKeyStoreType());
			keystore.load(sslProperties.getKeyStore().getInputStream(), sslProperties.getKeyStorePassword().toCharArray());
		} catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
			throw new ArrowheadException(ex.getMessage());
		}			
		final PrivateKey providerPrivateKey = Utilities.getPrivateKey(keystore, sslProperties.getKeyPassword());
		
		providerSecurityConfig.getTokenSecurityFilter().setAuthorizationPublicKey(authorizationPublicKey);
		providerSecurityConfig.getTokenSecurityFilter().setMyPrivateKey(providerPrivateKey);
	}
	
	//-------------------------------------------------------------------------------------------------
	private ServiceRegistryRequestDTO createServiceRegistryRequest(final String serviceDefinition, final String serviceUri, final HttpMethod httpMethod) {
		final ServiceRegistryRequestDTO serviceRegistryRequest = new ServiceRegistryRequestDTO();
		serviceRegistryRequest.setServiceDefinition(serviceDefinition);
		final SystemRequestDTO systemRequest = new SystemRequestDTO();
		systemRequest.setSystemName(mySystemName);
		systemRequest.setAddress(mySystemAddress);
		systemRequest.setPort(mySystemPort);		

		if (sslEnabled && tokenSecurityFilterEnabled) {
			systemRequest.setAuthenticationInfo(Base64.getEncoder().encodeToString(arrowheadService.getMyPublicKey().getEncoded()));
			serviceRegistryRequest.setSecure(ServiceSecurityType.TOKEN.name());
			serviceRegistryRequest.setInterfaces(List.of(SystemProviderWithPublishingConstants.INTERFACE_SECURE));
		} else if (sslEnabled) {
			systemRequest.setAuthenticationInfo(Base64.getEncoder().encodeToString(arrowheadService.getMyPublicKey().getEncoded()));
			serviceRegistryRequest.setSecure(ServiceSecurityType.CERTIFICATE.name());
			serviceRegistryRequest.setInterfaces(List.of(SystemProviderWithPublishingConstants.INTERFACE_SECURE));
		} else {
			serviceRegistryRequest.setSecure(ServiceSecurityType.NOT_SECURE.name());
			serviceRegistryRequest.setInterfaces(List.of(SystemProviderWithPublishingConstants.INTERFACE_INSECURE));
		}
		serviceRegistryRequest.setProviderSystem(systemRequest);
		serviceRegistryRequest.setServiceUri(serviceUri);
		serviceRegistryRequest.setMetadata(new HashMap<>());
		serviceRegistryRequest.getMetadata().put(SystemProviderWithPublishingConstants.HTTP_METHOD, httpMethod.name());
		return serviceRegistryRequest;
	}

	//-------------------------------------------------------------------------------------------------
	protected void checkCoreSystemReachability(final CoreSystem coreSystem) {
		if (arrowheadService.echoCoreSystem(coreSystem)) {
			logger.info("'{}' core system is reachable.", coreSystem.name());
		} else {
			logger.info("'{}' core system is NOT reachable.", coreSystem.name());
		}
	}
}