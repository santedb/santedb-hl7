/*
 * Copyright (C) 2021 - 2025, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
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
 * Date: 2024-3-26
 */
using DocumentFormat.OpenXml.Office2016.Drawing.ChartDrawing;
using SanteDB.Client.Configuration;
using SanteDB.Core.Configuration;
using SanteDB.Core.Model.Constants;
using SanteDB.Core.Security;
using SanteDB.Messaging.HL7.Messages;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;

namespace SanteDB.Messaging.HL7.Configuration.Feature
{
    /// <summary>
    /// HL7 Client configuration feature
    /// </summary>
    public class Hl7ClientConfigurationFeature : IClientConfigurationFeature
    {
        /// <summary>
        /// Configuration for enabling
        /// </summary>
        public const string CONFIG_ENABLED= "enabled";

        /// <summary>
        /// Local domain name
        /// </summary>
        public const string CONFIG_LOCAL_DOMAIN_NAME = "localAuthority";

        /// <summary>
        /// Facility identifier
        /// </summary>
        public const string CONFIG_FACILITY_ID = "facility";

        /// <summary>
        /// Security mode
        /// </summary>
        public const string CONFIG_SECURITY_MODE = "security";

        /// <summary>
        /// Listening address
        /// </summary>
        public const string CONFIG_LISTEN_ADDRESS = "address";
        private Hl7ConfigurationSection m_configuration;

        /// <summary>
        /// Configuration for the HL7 feature
        /// </summary>
        public Hl7ClientConfigurationFeature(InitialConfigurationManager configurationManager)
        {
            this.m_configuration = configurationManager.GetSection<Hl7ConfigurationSection>();
        }

        /// <inheritdoc/>
        public int Order => Int32.MaxValue;

        /// <inheritdoc/>
        public string Name => "hl7";

        /// <inheritdoc/>
        public ConfigurationDictionary<string, object> Configuration
        {
            get
            {
                var retVal = new ConfigurationDictionary<String, Object>();
                retVal.Add(CONFIG_ENABLED, this.m_configuration != null && this.m_configuration.Services.Any());
                retVal.Add(CONFIG_FACILITY_ID, this.m_configuration.LocalFacility);
                retVal.Add(CONFIG_LISTEN_ADDRESS, this.m_configuration.Services.FirstOrDefault()?.AddressXml);
                retVal.Add(CONFIG_LOCAL_DOMAIN_NAME, this.m_configuration.LocalAuthority?.DomainName);
                retVal.Add(CONFIG_SECURITY_MODE, this.m_configuration.Security.ToString());
                return retVal;
            }
        }

        /// <inheritdoc/>
        public string ReadPolicy => PermissionPolicyIdentifiers.ReadMetadata;

        /// <inheritdoc/>
        public string WritePolicy => PermissionPolicyIdentifiers.AlterSystemConfiguration;

        /// <inheritdoc/>
        public bool Configure(SanteDBConfiguration configuration, IDictionary<string, object> featureConfiguration)
        {
            var hl7Section = configuration.GetSection<Hl7ConfigurationSection>();
            if (!featureConfiguration.TryGetValue(CONFIG_ENABLED, out var enabled) && !(bool)enabled)
            {
                hl7Section.Services.Clear();
                return true;
            }
            else if (hl7Section == null)
            {
                hl7Section = new Hl7ConfigurationSection()
                {
                    BirthplaceClassKeys = new List<Guid>()
                    {
                        EntityClassKeys.StateOrProvince,
                        EntityClassKeys.PrecinctOrBorough,
                        EntityClassKeys.CityOrTown,
                        EntityClassKeys.ServiceDeliveryLocation,
                        EntityClassKeys.Country
                    },
                    LocalAuthority = new Core.Model.DataTypes.IdentityDomain("YOUR_LOCAL_V2_AUTHORITY", "Local Authority", $"2.25.{BitConverter.ToInt64(Guid.NewGuid().ToByteArray(), 0)}"),
                    SsnAuthority = new Core.Model.DataTypes.IdentityDomain("SSN", "Social Security Number", "2.16.840.1.113883.4.1"),
                    IdentifierReplacementBehavior = IdentifierReplacementMode.Specific,
                    LocalFacility = Guid.Empty,
                    Security = Hl7AuthenticationMethod.Msh8,
                    RequireAuthenticatedApplication = true,
                    StrictAssigningAuthorities = true,
                    StrictMetadataMatch = true,
                    Services = new List<Hl7ServiceDefinition>()
                    {
                        new Hl7ServiceDefinition()
                        {
                            AddressXml = "llp://0.0.0.0:2100",
                            Name = "default",
                            ReceiveTimeout = 20000,
                            MessageHandlers = new List<HandlerDefinition>()
                            {
                                new HandlerDefinition()
                                {
                                    HandlerType = new TypeReferenceConfiguration(typeof(QbpMessageHandler)),
                                    Types = new List<MessageDefinition>()
                                    {
                                        new MessageDefinition()
                                        {
                                            IsQuery = true,
                                            Name = "QBP^Q22"
                                        },
                                        new MessageDefinition()
                                        {
                                            IsQuery = true,
                                            Name = "QBP^Q23"
                                        }
                                    }
                                },
                                new HandlerDefinition()
                                {
                                    HandlerType = new TypeReferenceConfiguration(typeof(AdtMessageHandler)),
                                    Types = new List<MessageDefinition>()
                                    {
                                        new MessageDefinition()
                                        {
                                            IsQuery = false,
                                            Name = "ADT^A01"
                                        },
                                        new MessageDefinition()
                                        {
                                            IsQuery = false,
                                            Name = "ADT^A04"
                                        },
                                        new MessageDefinition()
                                        {
                                            IsQuery = false,
                                            Name = "ADT^A08"
                                        },
                                        new MessageDefinition()
                                        {
                                            IsQuery = false,
                                            Name = "ADT^A40"
                                        }
                                    }
                                }
                            }
                        }
                    }
                };
            }
           
            if(featureConfiguration.TryGetValue(CONFIG_FACILITY_ID, out var facilityIdRaw) && Guid.TryParse(facilityIdRaw.ToString(), out var facilityId))
            {
                hl7Section.LocalFacility = facilityId;
            }

            if(featureConfiguration.TryGetValue(CONFIG_LISTEN_ADDRESS, out var addressRaw))
            {
                if(!hl7Section.Services.Any())
                {
                    hl7Section.Services = new List<Hl7ServiceDefinition>()
                    {
                        new Hl7ServiceDefinition()
                        {
                            AddressXml = addressRaw.ToString(),
                            ReceiveTimeout = 20000,
                             MessageHandlers = new List<HandlerDefinition>()
                             {
                                 new HandlerDefinition()
                                {
                                    HandlerType = new TypeReferenceConfiguration(typeof(QbpMessageHandler)),
                                    Types = new List<MessageDefinition>()
                                    {
                                        new MessageDefinition()
                                        {
                                            IsQuery = true,
                                            Name = "QBP^Q22"
                                        },
                                        new MessageDefinition()
                                        {
                                            IsQuery = true,
                                            Name = "QBP^Q23"
                                        }
                                    }
                                },
                                new HandlerDefinition()
                                {
                                    HandlerType = new TypeReferenceConfiguration(typeof(AdtMessageHandler)),
                                    Types = new List<MessageDefinition>()
                                    {
                                        new MessageDefinition()
                                        {
                                            IsQuery = false,
                                            Name = "ADT^A01"
                                        },
                                        new MessageDefinition()
                                        {
                                            IsQuery = false,
                                            Name = "ADT^A04"
                                        },
                                        new MessageDefinition()
                                        {
                                            IsQuery = false,
                                            Name = "ADT^A08"
                                        },
                                        new MessageDefinition()
                                        {
                                            IsQuery = false,
                                            Name = "ADT^A40"
                                        }
                                    }
                                }
                             }
                        }
                    };
                }
                else
                {
                    hl7Section.Services.First().AddressXml = addressRaw.ToString();
                }
            }

            if(featureConfiguration.TryGetValue(CONFIG_LOCAL_DOMAIN_NAME, out var localDomainNameRaw))
            {
                hl7Section.LocalAuthority = new Core.Model.DataTypes.IdentityDomain()
                {
                    DomainName = localDomainNameRaw.ToString(),
                    Oid = $"2.25.{BitConverter.ToUInt64(Guid.NewGuid().ToByteArray(), 0)}"
                };
            }

            if(featureConfiguration.TryGetValue(CONFIG_SECURITY_MODE, out var securityModeRaw) && Enum.TryParse<Hl7AuthenticationMethod>(securityModeRaw.ToString(), out var securityMode))
            {
                hl7Section.Security = securityMode;
            }

            return true;

        }
    }
}
