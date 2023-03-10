﻿/*
 * Copyright (C) 2021 - 2023, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
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
 * Date: 2023-3-10
 */
using Newtonsoft.Json;
using SanteDB.Core.Model.DataTypes;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Xml.Serialization;

namespace SanteDB.Messaging.HL7.Configuration
{
    /// <summary>
    /// HL7 Notifications Configuration Element
    /// </summary>
    [ExcludeFromCodeCoverage]
    [XmlType(nameof(Hl7InterceptorConfigurationElement), Namespace = "http://santedb.org/configuration")]
    public class Hl7InterceptorConfigurationElement
    {

        /// <summary>
        /// Gets the XML type name of the notification
        /// </summary>
        [XmlAttribute("type"), JsonProperty("type")]
        public string InterceptorClassXml { get; set; }

        /// <summary>
        /// Gets or sets the notifier
        /// </summary>
        [XmlIgnore, JsonIgnore]
        public Type InterceptorClass { get => Type.GetType(this.InterceptorClassXml); set => this.InterceptorClassXml = value?.GetType().AssemblyQualifiedName; }

        /// <summary>
        /// Guards to filter the incoming data
        /// </summary>
        [XmlArray("guards"), XmlArrayItem("add"), JsonProperty("guards")]
        public List<String> Guards { get; set; }

        /// <summary>
        /// Represents endpoints
        /// </summary>
        [XmlArray("endpoints"), XmlArrayItem("add"), JsonProperty("endpoints")]
        public List<Hl7RemoteEndpointConfiguration> Endpoints { get; set; }

        /// <summary>
        /// Gets or sets the identity domains to notify the remote target of
        /// </summary>
        [XmlArray("domains"), XmlArrayItem("add"), JsonProperty("domains")]
        public List<IdentityDomain> ExportDomains { get; set; }

        /// <summary>
        /// Sets the version
        /// </summary>
        [XmlAttribute("hl7version"), JsonProperty("hl7version")]
        public string Version { get; set; }
    }
}