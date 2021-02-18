﻿/*
 * Portions Copyright 2019-2020, Fyfe Software Inc. and the SanteSuite Contributors (See NOTICE)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you 
 * may not use this file except in compliance with the License. You may 
 * obtain a copy of the License at 
 * 
 * http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations under 
 * the License.
 * 
 * User: fyfej (Justin Fyfe)
 * Date: 2019-11-27
 */
using NHapi.Base.Model;
using SanteDB.Messaging.HL7.TransportProtocol;

namespace SanteDB.Messaging.HL7
{
	/// <summary>
	/// Handler for HL7 message
	/// </summary>
	public interface IHL7MessageHandler
	{
		/// <summary>
		/// Handle a message
		/// </summary>
		IMessage HandleMessage(Hl7MessageReceivedEventArgs e);

        /// <summary>
        /// The triggers the handler supports
        /// </summary>
        string[] SupportedTriggers { get; }
	}
}