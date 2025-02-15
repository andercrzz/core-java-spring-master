/********************************************************************************
 * Copyright (c) 2020 {Lulea University of Technology}
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 
 *
 * Contributors: 
 *   {Lulea University of Technology} - implementation
 *   Arrowhead Consortia - conceptualization 
 ********************************************************************************/

package eu.arrowhead.common.dto.shared;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class DataManagerServicesResponseDTO implements Serializable {

	//=================================================================================================
	// members
	
	private static final long serialVersionUID = 2184859722224129210L;
	
	private List<String> services= new ArrayList<>();
	        
	//=================================================================================================
	// methods
	
	//-------------------------------------------------------------------------------------------------
	public DataManagerServicesResponseDTO() {}
	
	//-------------------------------------------------------------------------------------------------
	public List<String> getServices() { return services; }
	
	//-------------------------------------------------------------------------------------------------
	public void setServices(final List<String> services) { this.services = services; }

	//-------------------------------------------------------------------------------------------------
	@Override
	public String toString() {
		try {
			return new ObjectMapper().writeValueAsString(this);
		} catch (final JsonProcessingException ex) {
			return "toString failure";
		}
	}
}