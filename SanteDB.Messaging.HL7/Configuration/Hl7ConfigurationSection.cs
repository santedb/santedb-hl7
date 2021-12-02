/*
 * Copyright (C) 2021 - 2021, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
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
 * User: fyfej
 * Date: 2021-8-5
 */

using Newtonsoft.Json;
using SanteDB.Core;
using SanteDB.Core.Configuration;
using SanteDB.Core.Model.Attributes;
using SanteDB.Core.Model.DataTypes;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Xml.Serialization;

namespace SanteDB.Messaging.HL7.Configuration
{
    /// <summary>
    /// Represents the HL7 configuration
    /// </summary>
    [ExcludeFromCodeCoverage]
    [XmlType(nameof(Hl7ConfigurationSection), Namespace = "http://santedb.org/configuration")]
    public class Hl7ConfigurationSection : IConfigurationSection
    {
        /// <summary>
        /// Create a new HL7 Configuration section
        /// </summary>
        public Hl7ConfigurationSection()
        {
        }

        /// <summary>
        /// Represents the local domain
        /// </summary>
        [XmlElement("localAuthority"), JsonProperty("localAuthority")]
        [DisplayName("Local Domain"), Description("The local identity domain. When this identity domain appears in the CX.4 of a message, it will be assumed to be an internal key")]
        [TypeConverter(typeof(ExpandableObjectConverter))]
        public AssigningAuthority LocalAuthority { get; set; }

        /// <summary>
        /// Security method
        /// </summary>
        [XmlAttribute("security"), JsonProperty("security")]
        [DisplayName("Authentication Mode"), Description("The method of authenticating clients messages. If you're using SLLP then this setting controls the authentication of the MSH-3 (sending application) and the client certificate authenticates the device, if you're using LLP then this authenticates the device and software")]
        public AuthenticationMethod Security { get; set; }

        /// <summary>
        /// If no security method is being used, the principal of the anonymous user
        /// </summary>
        [XmlAttribute("noAuthSecret"), JsonProperty("noAuthSecret")]
        [DisplayName("No Auth Secret"), Description("If you set the authentication mode to NONE then the secret for the (MSH-3) which all HL7 messages will run on")]
        public String NoAuthenticationSecret { get; set; }

        /// <summary>
        /// The address to which to bind
        /// </summary>
        /// <remarks>A full Uri is required and must be tcp:// or mllp://</remarks>
        [XmlArray("services"), XmlArrayItem("add"), JsonProperty("services")]
        [DisplayName("HL7 Services"), Description("The HL7 endpoints and services offered on those endpoints")]
        public List<Hl7ServiceDefinition> Services { get; set; }

        /// <summary>
        /// Gets or sets the facilit
        /// </summary>
        [XmlElement("facility"), JsonProperty("facility")]
        [DisplayName("Receiving Facility ID"), Description("The UUID of the local facility (Place) which will be used to populate the sending facility information on responses")]
        public Guid LocalFacility { get; set; }

        /// <summary>
        /// Gets or sets the authority for SSN
        /// </summary>
        [XmlElement("ssnAuthority"), JsonProperty("ssnAuthority")]
        [TypeConverter(typeof(ExpandableObjectConverter))]
        [DisplayName("SSN Authority"), Description("The assigning authority which should be used when PID-19 (SSN) is provided")]
        public AssigningAuthority SsnAuthority { get; set; }

        /// <summary>
        /// Birthplace class keys
        /// </summary>
        [XmlArray("birthplaceClasses"), XmlArrayItem("add"), JsonProperty("birthplaceClasses")]
        [DisplayName("Birthplace Types"), Description("The HL7 PID segment for birthplace is a textual string. This setting identifies the class types to use when attempting to resolve the birthplace of the patient")]
        public List<Guid> BirthplaceClassKeys { get; set; }

        /// <summary>
        /// Identifier expiration behavior
        /// </summary>
        [XmlAttribute("idReplacement"), JsonProperty("idReplacement")]
        [DisplayName("Identifier Replacement"), Description("Controls how expiration of identifiers is handled. AnyInDomain means that all identifiers in the same identity domain are expired and the current value is used, SameDomain only expires matching identifiers in the same domain")]
        public IdentifierReplacementMode IdentifierReplacementBehavior { get; set; }

        /// <summary>
        /// When true, indicates strict birthplace matching
        /// </summary>
        [XmlAttribute("strictMetadata"), JsonProperty("strictMetadata")]
        [DisplayName("Strict Metadata"), Description("When true, all metadata contained within an inbound HL7 message must exactly match that in SanteDB or else a message processing error is thrown.")]
        public bool StrictMetadataMatch { get; set; }

        /// <summary>
        /// True if authenticated applications (Application Secret) is required
        /// </summary>
        [XmlAttribute("requireAppAuth"), JsonProperty("requireAppAuth")]
        [DisplayName("Require Application Authentication"), Description("When true, applications must be authenticated in addition to the device, when false only device level authentication is required.")]
        public bool RequireAuthenticatedApplication { get; set; }

        /// <summary>
        /// Strict assigning authority
        /// </summary>
        [XmlAttribute("strictCx4"), JsonProperty("strictCx4")]
        [DisplayName("Strict CX4"), Description("When true, allows senders to submit PID-3 data with no CX.4. SanteDB will resolve the CX.4 based on the sending facility and device")]
        public bool StrictAssigningAuthorities { get; set; }
    }

    /// <summary>
    /// Identifier expiration behavior mode
    /// </summary>
    [XmlType(nameof(IdentifierReplacementMode), Namespace = "http://santedb.org/configuration")]
    public enum IdentifierReplacementMode
    {
        /// <summary>
        /// When an identifier is marked as "expired" it shall replace any active identifier in the identity domain
        /// </summary>
        /// <remarks>When this setting mode is enabled the processor will void (remove) any existing identifier in any identity domain where the submitted message
        /// contains an identifier in that identity domain with an effective time on "today's date". Any identifiers with an expiration date must match value for value.</remarks>
        [XmlEnum("any-in-domain")]
        AnyInDomain = 0,

        /// <summary>
        /// When an identifier is marked as "expired" it will only replace an active identity with the same value
        /// </summary>
        [XmlEnum("specific")]
        Specific = 1
    }

    /// <summary>
    /// Handler definition
    /// </summary>
    [ExcludeFromCodeCoverage]
    [XmlType(nameof(HandlerDefinition), Namespace = "http://santedb.org/configuration")]
    public class HandlerDefinition
    {
        /// <summary>
        /// The handler
        /// </summary>
        private IHL7MessageHandler m_handler;

        /// <summary>
        /// Handler defn ctor
        /// </summary>
        public HandlerDefinition()
        {
            this.Types = new List<MessageDefinition>();
        }

        /// <summary>
        /// Gets or sets the handler
        /// </summary>
        [XmlIgnore, JsonIgnore, Browsable(false)]
        public IHL7MessageHandler Handler
        {
            get
            {
                if (this.m_handler == null)
                {
                    this.m_handler = this.HandlerType.Type.CreateInjected() as IHL7MessageHandler;
                }
                return this.m_handler;
            }
            set
            {
                this.HandlerType = new TypeReferenceConfiguration(value.GetType());
            }
        }

        /// <summary>
        /// Type name of the handler
        /// </summary>
        [XmlAttribute("type"), JsonProperty("type"), Browsable(false)]
        public string HandlerTypeXml
        {
            get => null;
            set => this.HandlerType = new TypeReferenceConfiguration(Type.GetType(value));
        }

        /// <summary>
        /// Gets or sets the handler type
        /// </summary>
        [XmlElement("handler"), JsonProperty("handler")]
        [DisplayName("Message Handler"), Description("The message handler which can process messages which carry the events listed in this service")]
        [Binding(typeof(IHL7MessageHandler))]
        [Editor("SanteDB.Configuration.Editors.TypeSelectorEditor, SanteDB.Configuration", "System.Drawing.Design.UITypeEditor, System.Drawing")]
        public TypeReferenceConfiguration HandlerType { get; set; }

        /// <summary>
        /// Message types that trigger this (MSH-9)
        /// </summary>
        [XmlElement("event"), JsonProperty("event")]
        [DisplayName("Events"), Description("The message events which are routed to the message handler")]
        public List<MessageDefinition> Types { get; set; }

        /// <summary>
        /// Get the string representation
        /// </summary>
        public override string ToString() => this.HandlerType?.Type.GetCustomAttribute<DisplayNameAttribute>()?.DisplayName ?? this.HandlerType?.Type.Name;
    }

    /// <summary>
    /// Security methods
    /// </summary>
    [XmlType(nameof(AuthenticationMethod), Namespace = "http://santedb.org/configuration")]
    public enum AuthenticationMethod
    {
        /// <summary>
        /// No security
        /// </summary>
        None,

        /// <summary>
        /// Use MSH-8 for authentication
        /// </summary>
        Msh8,

        /// <summary>
        /// Use SFT-4 for authentication
        /// </summary>
        Sft4
    }

    /// <summary>
    /// Message definition
    /// </summary>
    [ExcludeFromCodeCoverage]
    [XmlType(nameof(MessageDefinition), Namespace = "http://santedb.org/configuration")]
    public class MessageDefinition
    {
        /// <summary>
        /// Gets or sets a value identifying whether this is a query
        /// </summary>
        [XmlAttribute("isQuery"), JsonProperty("isQuery")]
        [DisplayName("Query Event"), Description("When true, execute once tracking will not be used")]
        public bool IsQuery { get; set; }

        /// <summary>
        /// Gets or sets the name
        /// </summary>
        [XmlAttribute("name"), JsonProperty("name")]
        [DisplayName("Event"), Description("The HL7 event identifier, for example ADT^A01")]
        public string Name { get; set; }

        /// <summary>
        /// Represent as a string
        /// </summary>
        public override string ToString() => this.Name;
    }

    /// <summary>
    /// Service definition
    /// </summary>
    [ExcludeFromCodeCoverage]
    [XmlType(nameof(Hl7ServiceDefinition), Namespace = "http://santedb.org/configuration")]
    public class Hl7ServiceDefinition : Hl7EndpointConfiguration
    {
        /// <summary>
        /// Service defn ctor
        /// </summary>
        public Hl7ServiceDefinition()
        {
            this.MessageHandlers = new List<HandlerDefinition>();
        }

        /// <summary>
        /// Gets or sets the handlers
        /// </summary>
        [XmlArray("messages"), XmlArrayItem("add"), JsonProperty("messages")]
        [DisplayName("Messages"), Description("The message(s) which this service will accept and process")]
        public List<HandlerDefinition> MessageHandlers { get; set; }

        /// <summary>
        /// Gets or sets the name of the defintiion
        /// </summary>
        [XmlAttribute("name"), JsonProperty("name")]
        [DisplayName("Name"), Description("The name of the service for logging and debugging purposes")]
        public string Name { get; set; }

        /// <summary>
        /// Represent as a string
        /// </summary>
        public override string ToString() => this.Name;
    }
}