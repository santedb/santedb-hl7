﻿/*
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
using SanteDB.Core.Configuration;
using SanteDB.Core.Diagnostics;
using SanteDB.Core.Security.Configuration;
using SanteDB.Docker.Core;
using SanteDB.Messaging.HL7.Configuration;
using SanteDB.Messaging.HL7.TransportProtocol;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace SanteDB.Messaging.HL7.Docker
{
    /// <summary>
    /// Configures the HL7 feature in docker
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class Hl7DockerFeature : IDockerFeature
    {
        /// <summary>
        /// Authentication settings
        /// </summary>
        public const string AuthenticationSetting = "AUTHENTICATION";

        /// <summary>
        /// Setting for local IDs
        /// </summary>
        public const string LocalAuthoritySetting = "LOCAL_DOMAIN";

        /// <summary>
        /// Setting for SSN IDs
        /// </summary>
        public const string SsnAuthoritySetting = "SSN_DOMAIN";

        /// <summary>
        /// Setting for LISTEN URI
        /// </summary>
        public const string ListenUriSetting = "LISTEN";

        /// <summary>
        /// Setting for timeouts
        /// </summary>
        public const string TimeoutSetting = "TIMEOUT";

        /// <summary>
        /// Setting for server SSL
        /// </summary>
        public const string ServerCertificateSetting = "SERVER_CERT";

        /// <summary>
        /// Setting for client AUTH
        /// </summary>
        public const string ClientCertificateSetting = "CLIENT_AUTH";

        // Tracer
        private readonly Tracer m_tracer = Tracer.GetTracer(typeof(Hl7DockerFeature));

        /// <summary>
        /// Get the ID of this feature
        /// </summary>
        public string Id => "HL7";

        /// <summary>
        /// Get the settings for this feature
        /// </summary>
        public IEnumerable<string> Settings => new String[] { TimeoutSetting, AuthenticationSetting, LocalAuthoritySetting, SsnAuthoritySetting, ListenUriSetting, ServerCertificateSetting, ClientCertificateSetting };

        /// <summary>
        /// Configure the message handler
        /// </summary>
        public void Configure(SanteDBConfiguration configuration, IDictionary<string, string> settings)
        {
            var hl7Configuration = configuration.GetSection<Hl7ConfigurationSection>();
            if (hl7Configuration == null)
            {
                hl7Configuration = DockerFeatureUtils.LoadConfigurationResource<Hl7ConfigurationSection>("SanteDB.Messaging.HL7.Docker.Hl7Feature.xml");
                configuration.AddSection(hl7Configuration);
            }

            // first the security
            if (settings.TryGetValue(AuthenticationSetting, out string auth))
            {
                if (!Enum.TryParse<Hl7AuthenticationMethod>(auth, true, out var authResult))
                {
                    this.m_tracer.TraceError($"Couldn't understand {auth}, valid values are NONE, MSH8, or SFT4");
                    throw new ArgumentOutOfRangeException($"{auth} not valid setting - valid values are NONE, MSH8, or SFT4");
                }
                hl7Configuration.Security = authResult;
            }

            // Next, local domain
            if (settings.TryGetValue(LocalAuthoritySetting, out string localAuth))
            {
                hl7Configuration.LocalAuthority = new Core.Model.DataTypes.IdentityDomain(localAuth, localAuth, null);
            }

            // Next the SSN domain
            if (settings.TryGetValue(SsnAuthoritySetting, out string ssnAuth))
            {
                hl7Configuration.SsnAuthority = new Core.Model.DataTypes.IdentityDomain(ssnAuth, ssnAuth, null);
            }

            // Next listen address
            if (settings.TryGetValue(ListenUriSetting, out string listenStr))
            {
                if (!Uri.TryCreate(listenStr, UriKind.Absolute, out Uri listenUri))
                {
                    throw new ArgumentOutOfRangeException($"{listenStr} is not a valid URL");
                }

                hl7Configuration.Services.ForEach(o => o.AddressXml = listenStr);
            }

            // Timeouts
            if (settings.TryGetValue(TimeoutSetting, out string timeoutStr))
            {
                if (!Int32.TryParse(timeoutStr, out int timeout))
                {
                    this.m_tracer.TraceError("Invalid timeout");
                    throw new ArgumentOutOfRangeException($"{timeoutStr} is not a valid timeout");
                }
                hl7Configuration.Services.ForEach(o => o.ReceiveTimeout = timeout);
            }

            // Service certificates
            if (settings.TryGetValue(ServerCertificateSetting, out String serverCertificate))
            {
                hl7Configuration.Services.ForEach(svc => svc.Configuration = new SllpTransport.SllpConfigurationObject()
                {
                    CheckCrl = true,
                    ServerCertificate = new X509ConfigurationElement()
                    {
                        FindType = System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                        FindValue = serverCertificate,
                        StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine,
                        StoreName = System.Security.Cryptography.X509Certificates.StoreName.My
                    },
                    EnableClientCertNegotiation = settings.TryGetValue(ClientCertificateSetting, out string clientCert),
                    ClientCaCertificate = new X509ConfigurationElement()
                    {
                        FindType = System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                        FindValue = clientCert,
                        StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine,
                        StoreName = System.Security.Cryptography.X509Certificates.StoreName.My
                    }
                });
            }

            // Add services
            var serviceConfiguration = configuration.GetSection<ApplicationServiceContextConfigurationSection>().ServiceProviders;
            if (!serviceConfiguration.Any(s => s.Type == typeof(HL7MessageHandler)))
            {
                serviceConfiguration.Add(new TypeReferenceConfiguration(typeof(HL7MessageHandler)));
            }
        }
    }
}