package ai.aitia.demo.car_provider_with_publishing.entity;

public class RegisteredSystem {

	//=================================================================================================
	// members

    private final int id;
    private String name;
    private String endpoint;

    //=================================================================================================
	// methods

	//-------------------------------------------------------------------------------------------------

	public RegisteredSystem(final int id, final String name, final String endpoint) {
		this.id = id;
		this.name = name;
		this.endpoint = endpoint;
	}

    // Getters and Setters
    public int getId() { return id; }

    public String getName() { return name; }
    public void setName(final String name) { this.name = name; }

    public String getEndpoint() { return endpoint; }
    public void setEndpoint(final String endpoint) { this.endpoint = endpoint; }
}