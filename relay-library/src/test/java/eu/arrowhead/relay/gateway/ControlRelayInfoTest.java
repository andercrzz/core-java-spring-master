/********************************************************************************
 * Copyright (c) 2021 AITIA
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

package eu.arrowhead.relay.gateway;

import javax.jms.MessageProducer;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class ControlRelayInfoTest {

	//=================================================================================================
	// methods
	
	//-------------------------------------------------------------------------------------------------
	@Test(expected = IllegalArgumentException.class)
	public void testConstructorControlRequestMessageSenderNull() {
		try {
			new ControlRelayInfo(null, null);
		} catch (final Exception ex) {
			Assert.assertEquals("controlRequestMessageSender is null.", ex.getMessage());
			
			throw ex;
		}
	}
	
	//-------------------------------------------------------------------------------------------------
	@Test(expected = IllegalArgumentException.class)
	public void testConstructorControlResponseMessageSenderNull() {
		final MessageProducer producer = Mockito.mock(MessageProducer.class);
		
		try {
			new ControlRelayInfo(producer, null);
		} catch (final Exception ex) {
			Assert.assertEquals("controlResponseMessageSender is null.", ex.getMessage());
			
			throw ex;
		}
	}
}