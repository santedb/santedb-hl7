/*
 * Copyright (C) 2021 - 2024, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
 * Copyright (C) 2019 - 2021, Fyfe Software Inc. and the SanteSuite Contributors
 * Portions Copyright (C) 2015-2018 Mohawk College of Applied Arts and Technology
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
 */
using Newtonsoft.Json;
using SanteDB.Messaging.HL7.Client;
using SanteDB.Messaging.HL7.TransportProtocol;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Xml.Serialization;

namespace SanteDB.Messaging.HL7.Configuration
{
    /// <summary>
    /// Represents HL7 endpoint configuration data
    /// </summary>
    [ExcludeFromCodeCoverage]
    [XmlType(nameof(Hl7EndpointConfiguration), Namespace = "http://santedb.org/configuration")]
    public class Hl7EndpointConfiguration
    {

        // Address XML
        private string m_addressXml = null;

        /// <summary>
        /// Gets or sets the address of the service
        /// </summary>
        [XmlAttribute("address"), JsonProperty("address")]
        [DisplayName("Endpoint"), Description("The endpoint address in the format of a URL such as [s]llp://[host]:[port]")]
        public String AddressXml
        {
            get => this.m_addressXml;
            set
            {
                this.m_addressXml = value;
                if (value?.StartsWith("sllp") == true && this.Configuration == null)
                {
                    this.Configuration = new SllpTransport.SllpConfigurationObject();
                }
            }
        }

        /// <summary>
        /// Gets the listening address
        /// </summary>
        [XmlIgnore, JsonIgnore, Browsable(false)]
        public Uri Address => new Uri(this.AddressXml);

        /// <summary>
        /// Attributes
        /// </summary>
        [XmlElement("sllp", Type = typeof(SllpTransport.SllpConfigurationObject)), JsonProperty("sllpConfiguration")]
        [DisplayName("Transport Options"), Description("When selecting a transport that requires additional configuration, these are the settings to use")]
        [TypeConverter(typeof(ExpandableObjectConverter))]
        public object Configuration { get; set; }

        /// <summary>
        /// Gets or sets the timeout
        /// </summary>
        [XmlAttribute("receiveTimeout"), JsonProperty("receiveTimeout")]
        [DisplayName("Receive Timeout (ms)"), Description("The maximum amount of time to wait on the socket to receive data")]
        public int ReceiveTimeout { get; set; }


    }

    /// <summary>
    /// Represents a remote endpoint
    /// </summary>
    [ExcludeFromCodeCoverage]
    [XmlType(nameof(Hl7RemoteEndpointConfiguration), Namespace = "http://santedb.org/configuration")]
    public class Hl7RemoteEndpointConfiguration : Hl7EndpointConfiguration
    {

        // Sender
        private MllpMessageSender m_sender;

        /// <summary>
        /// Gets the security token
        /// </summary>
        [XmlAttribute("securityToken"), JsonProperty("securityToken")]
        public String SecurityToken { get; set; }

        /// <summary>
        /// Gets the receiving facility
        /// </summary>
        [XmlAttribute("recievingFacility"), JsonProperty("recievingFacility")]
        public String ReceivingFacility { get; set; }

        /// <summary>
        /// Gets the receiving facility
        /// </summary>
        [XmlAttribute("recievingDevice"), JsonProperty("recievingDevice")]
        public String ReceivingDevice { get; set; }

        /// <summary>
        /// Get the message sender
        /// </summary>
        /// <returns></returns>
        public MllpMessageSender GetSender()
        {
            if (this.m_sender == null)
            {
                this.m_sender = new MllpMessageSender(this.Address, (this.Configuration as SllpTransport.SllpConfigurationObject)?.ClientCaCertificate?.Certificate, (this.Configuration as SllpTransport.SllpConfigurationObject)?.ServerCertificate?.Certificate);
            }

            return this.m_sender;
        }

    }
}