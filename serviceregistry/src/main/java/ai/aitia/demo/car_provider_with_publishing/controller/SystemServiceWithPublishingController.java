package ai.aitia.demo.car_provider_with_publishing.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import ai.aitia.demo.car_common.dto.RegisteredSystemRequestDTO;
import ai.aitia.demo.car_common.dto.RegisteredSystemResponseDTO;
import ai.aitia.demo.car_provider_with_publishing.database.DTOConverter;
import ai.aitia.demo.car_provider_with_publishing.database.InMemorySystemDB;
import ai.aitia.demo.car_provider_with_publishing.entity.RegisteredSystem;
import eu.arrowhead.application.skeleton.publisher.event.EventTypeConstants;
import eu.arrowhead.application.skeleton.publisher.event.PresetEventType;
import eu.arrowhead.application.skeleton.publisher.service.PublisherService;
import eu.arrowhead.common.exception.BadPayloadException;
import eu.arrowhead.core.serviceregistry.SystemProviderWithPublishingConstants;

@RestController
@RequestMapping(SystemProviderWithPublishingConstants.SYSTEM_URI)
public class SystemServiceWithPublishingController {
	
	//=================================================================================================
	// members

	
	private static int counter = 0;
	
	@Autowired
	private InMemorySystemDB systemDB;
	
	@Autowired
	private PublisherService publisherService;
	
	@Value( SystemProviderWithPublishingConstants.$SERVICE_LIMIT_WD )
	private int serviceLimit;

	//=================================================================================================
	// methods
	//-------------------------------------------------------------------------------------------------
	@GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody public List<RegisteredSystemResponseDTO> getSystems(@RequestParam(name = SystemProviderWithPublishingConstants.REQUEST_PARAM_NAME, required = false) final String name,
													  @RequestParam(name = SystemProviderWithPublishingConstants.REQUEST_PARAM_ENDPOINT, required = false) final String endpoint) {
		++counter;
		
		publisherService.publish(PresetEventType.REQUEST_RECEIVED, Map.of(EventTypeConstants.EVENT_TYPE_REQUEST_RECEIVED_METADATA_REQUEST_TYPE, HttpMethod.GET.name()), SystemProviderWithPublishingConstants.SYSTEM_URI);
		
		final List<RegisteredSystemResponseDTO> response = new ArrayList<>();
		for (final RegisteredSystem system : systemDB.getAll()) {
			boolean toAdd = true;
			if (name != null && !name.isBlank() && !system.getName().equalsIgnoreCase(name)) {
				toAdd = false;
			}
			if (endpoint != null && !endpoint.isBlank() && !system.getEndpoint().equalsIgnoreCase(endpoint)) {
				toAdd = false;
			}
			if (toAdd) {
				response.add(DTOConverter.convertSystemToSystemResponseDTO(system));
			}
		}
		
		if (counter > serviceLimit) {
			System.exit(0);
		}
		
		return response;
	}
	
	//-------------------------------------------------------------------------------------------------
	@GetMapping(path = SystemProviderWithPublishingConstants.BY_ID_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody public RegisteredSystemResponseDTO getSystemById(@PathVariable(value = SystemProviderWithPublishingConstants.PATH_VARIABLE_ID) final int id) {
		return DTOConverter.convertSystemToSystemResponseDTO(systemDB.getById(id));
	}
	
	//-------------------------------------------------------------------------------------------------
	@PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody public RegisteredSystemResponseDTO createSystem(@RequestBody final RegisteredSystemRequestDTO dto) {
		if (dto.getName() == null || dto.getName().isBlank()) {
			throw new BadPayloadException("name is null or blank");
		}
		if (dto.getEndpoint() == null || dto.getEndpoint().isBlank()) {
			throw new BadPayloadException("endpoint is null or blank");
		}
		final RegisteredSystem system = systemDB.create(dto.getName(), dto.getEndpoint());
		
		return DTOConverter.convertSystemToSystemResponseDTO(system);
	}
	
	//-------------------------------------------------------------------------------------------------
	@PutMapping(path = SystemProviderWithPublishingConstants.BY_ID_PATH, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody public RegisteredSystemResponseDTO updateCar(@PathVariable(name = SystemProviderWithPublishingConstants.PATH_VARIABLE_ID) final int id, @RequestBody final RegisteredSystemRequestDTO dto) {
		if (dto.getName() == null || dto.getName().isBlank()) {
			throw new BadPayloadException("name is null or blank");
		}
		if (dto.getEndpoint() == null || dto.getEndpoint().isBlank()) {
			throw new BadPayloadException("endpoint is null or blank");
		}
		final RegisteredSystem system = systemDB.updateById(id, dto.getName(), dto.getEndpoint());
		
		return DTOConverter.convertSystemToSystemResponseDTO(system);
	}
	
	//-------------------------------------------------------------------------------------------------
	@DeleteMapping(path = SystemProviderWithPublishingConstants.BY_ID_PATH)
	public void removeCarById(@PathVariable(value = SystemProviderWithPublishingConstants.PATH_VARIABLE_ID) final int id) {
		systemDB.removeById(id);
	}
}