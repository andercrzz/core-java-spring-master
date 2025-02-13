package eu.arrowhead.core.serviceregistry;

public class SystemProviderWithPublishingConstants {
	
	//=================================================================================================
	// members
	
	public static final String BASE_PACKAGE = "ai.aitia";
	
	public static final String CREATE_SYSTEM_SERVICE_DEFINITION = "create-system";
	public static final String GET_SYSTEM_SERVICE_DEFINITION = "get-system";
	public static final String INTERFACE_SECURE = "HTTP-SECURE-JSON";
	public static final String INTERFACE_INSECURE = "HTTP-INSECURE-JSON";
	public static final String HTTP_METHOD = "http-method";
	public static final String SYSTEM_URI = "/system";
	public static final String BY_ID_PATH = "/{id}";
	public static final String PATH_VARIABLE_ID = "id";
	public static final String REQUEST_PARAM_KEY_NAME = "request-param-name";
	public static final String REQUEST_PARAM_NAME = "name";
	public static final String REQUEST_PARAM_KEY_ENDPOINT = "request-param-endpoint";
	public static final String REQUEST_PARAM_ENDPOINT = "endpoint";
	
	public static final String SERVICE_LIMIT="service_limit";
	public static final int DEFAULT_SERVICE_LIMIT=200;
	public static final String $SERVICE_LIMIT_WD="${"+SERVICE_LIMIT+":"+DEFAULT_SERVICE_LIMIT+"}";
	
	//=================================================================================================
	// assistant methods

	//-------------------------------------------------------------------------------------------------
	private SystemProviderWithPublishingConstants() {
		throw new UnsupportedOperationException();
	}
}
