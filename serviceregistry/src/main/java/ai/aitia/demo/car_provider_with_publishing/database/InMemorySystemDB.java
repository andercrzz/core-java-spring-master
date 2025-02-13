package ai.aitia.demo.car_provider_with_publishing.database;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import ai.aitia.demo.car_provider_with_publishing.entity.RegisteredSystem;
import eu.arrowhead.common.exception.InvalidParameterException;

@Component
public class InMemorySystemDB extends ConcurrentHashMap<Integer, RegisteredSystem> {

	//=================================================================================================
	// members
	
	private static final long serialVersionUID = -2462387539362748691L;
	
	private int idCounter = 0;
	
	//=================================================================================================
	// methods

	//-------------------------------------------------------------------------------------------------
	public RegisteredSystem create(final String name, final String endpoint) {
		if (name == null || name.isBlank()) {
			throw new InvalidParameterException("name is null or empty");
		}		
		if (endpoint == null || endpoint.isBlank()) {
			throw new InvalidParameterException("endpoint is null or empty");
		}
		
		idCounter++;
		this.put(idCounter, new RegisteredSystem(idCounter, name.toLowerCase().trim(), endpoint.toLowerCase().trim()));
		return this.get(idCounter);
	}
	
	//-------------------------------------------------------------------------------------------------
	public List<RegisteredSystem> getAll() {
		return List.copyOf(this.values());
	}
	
	//-------------------------------------------------------------------------------------------------
	public RegisteredSystem getById(final int id) {
		if (this.containsKey(id)) {
			return this.get(id);
		} else {
			throw new InvalidParameterException("id '" + id + "' not exists");
		}
	}
	
	//-------------------------------------------------------------------------------------------------
	public RegisteredSystem updateById(final int id, final String name, final String endpoint) {
		if (this.containsKey(id)) {
			final RegisteredSystem system = this.get(id);
			if (name!= null && !name.isBlank()) {
				system.setName(name);
			}
			if (endpoint != null && !endpoint.isBlank()) {
				system.setEndpoint(endpoint);
			}
			this.put(id, system);
			return system;
		} else {
			throw new InvalidParameterException("id '" + id + "' not exists");
		}
	}
	
	//-------------------------------------------------------------------------------------------------
	public void removeById(final int id) {
		if (this.containsKey(id)) {
			this.remove(id);
		}
	}
}
