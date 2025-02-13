package ai.aitia.demo.car_provider_with_publishing.database;

import java.util.ArrayList;
import java.util.List;

import org.springframework.util.Assert;

import ai.aitia.demo.car_common.dto.RegisteredSystemResponseDTO;
import ai.aitia.demo.car_provider_with_publishing.entity.RegisteredSystem;

public class DTOConverter {

	
	//=================================================================================================
	// methods
	
	//-------------------------------------------------------------------------------------------------
	public static RegisteredSystemResponseDTO convertSystemToSystemResponseDTO(final RegisteredSystem system) {
		Assert.notNull(system, "System is null");
		return new RegisteredSystemResponseDTO(system.getId(), system.getName(), system.getEndpoint());
	}
	
	//-------------------------------------------------------------------------------------------------
	public static List<RegisteredSystemResponseDTO> convertSystemListToSystemResponseDTOList(final List<RegisteredSystem> systems) {
		Assert.notNull(systems, "system list is null");
		final List<RegisteredSystemResponseDTO> systemResponse = new ArrayList<>(systems.size());
		for (final RegisteredSystem system : systems) {
			systemResponse.add(convertSystemToSystemResponseDTO(system));
		}
		return systemResponse;
	}

	//=================================================================================================
	// assistant methods

	//-------------------------------------------------------------------------------------------------
	public DTOConverter() {
		throw new UnsupportedOperationException(); 
	}
}
