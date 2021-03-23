using SanteDB.Core.Configuration;
using SanteDB.Docker.Core;
using SanteDB.Messaging.HL7.Configuration;
using SanteDB.Messaging.HL7.TransportProtocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SanteDB.Messaging.HL7.Docker
{
    /// <summary>
    /// Configures the HL7 feature in docker
    /// </summary>
    public class Hl7Feature : IDockerFeature
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
            if(hl7Configuration == null)
            {
                hl7Configuration = DockerFeatureUtils.LoadConfigurationResource<Hl7ConfigurationSection>("SanteDB.Messaging.HL7.Docker.Hl7Feature.xml");
                configuration.AddSection(hl7Configuration);
            }

            // first the security 
            if(settings.TryGetValue(AuthenticationSetting, out string auth))
            {
                if(!Enum.TryParse<AuthenticationMethod>(auth, true, out AuthenticationMethod authResult)) {
                    throw new ArgumentOutOfRangeException($"Couldn't understand {auth}, valid values are NONE, MSH8, or SFT4");
                }
                hl7Configuration.Security = authResult;
            }

            // Next, local domain
            if(settings.TryGetValue(LocalAuthoritySetting, out string localAuth))
            {
                hl7Configuration.LocalAuthority = new Core.Model.DataTypes.AssigningAuthority(localAuth, localAuth, null);
            }

            // Next the SSN domain
            if(settings.TryGetValue(SsnAuthoritySetting, out string ssnAuth))
            {
                hl7Configuration.SsnAuthority = new Core.Model.DataTypes.AssigningAuthority(ssnAuth, ssnAuth, null);
            }

            // Next listen address
            if(settings.TryGetValue(ListenUriSetting, out string listenStr))
            {
                if(!Uri.TryCreate(listenStr, UriKind.Absolute, out Uri listenUri) )
                {
                    throw new ArgumentOutOfRangeException($"{listenStr} is not a valid URL");
                }

                hl7Configuration.Services.ForEach(o => o.AddressXml = listenStr);
            }

            // Timeouts
            if(settings.TryGetValue(TimeoutSetting, out string timeoutStr))
            {
                if(!Int32.TryParse(timeoutStr, out int timeout))
                {
                    throw new ArgumentOutOfRangeException("Invalid timeout");
                }
                hl7Configuration.Services.ForEach(o => o.ReceiveTimeout = timeout);
            }

            // Service certificates
            if(settings.TryGetValue(ServerCertificateSetting, out String serverCertificate))
            {
                hl7Configuration.Services.ForEach(svc => svc.Configuration = new SllpTransport.SllpConfigurationObject()
                {
                    CheckCrl = true,
                    ServerCertificate = new Hl7X509ConfigurationElement()
                    {
                        FindType = System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                        FindValue = serverCertificate,
                        StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine,
                        StoreName = System.Security.Cryptography.X509Certificates.StoreName.My
                    },
                    EnableClientCertNegotiation = settings.TryGetValue(ClientCertificateSetting, out string clientCert),
                    ClientCaCertificate = new Hl7X509ConfigurationElement()
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
