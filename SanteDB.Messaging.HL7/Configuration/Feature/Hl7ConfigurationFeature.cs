using SanteDB.Core.Configuration;
using SanteDB.Core.Model.Constants;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.Messages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SanteDB.Messaging.HL7.Configuration.Feature
{
    /// <summary>
    /// Configuration for HL7 message handler
    /// </summary>
    public class Hl7ConfigurationFeature : IFeature
    {

        // Configuration for the feature
        private Hl7ConfigurationSection m_configuration;

        /// <summary>
        /// Gets the configuration for this object
        /// </summary>
        public object Configuration
        {
            get => this.m_configuration;
            set => this.m_configuration = (Hl7ConfigurationSection)value;
        }

        /// <summary>
        /// Gets the type of configuration section for this panel
        /// </summary>
        public Type ConfigurationType => typeof(Hl7ConfigurationSection);

        /// <summary>
        /// Gets the description of the configuration feature
        /// </summary>
        public string Description => "Configures the HL7 Version 2.x receiver";

        /// <summary>
        /// The flags for this option
        /// </summary>
        public FeatureFlags Flags => FeatureFlags.AutoSetup;

        /// <summary>
        /// Gets the group
        /// </summary>
        public string Group => FeatureGroup.Messaging;

        /// <summary>
        /// Gets the name of the feature
        /// </summary>
        public string Name => "HL7 Version 2.x";

        /// <summary>
        /// Create the installation tasks
        /// </summary>
        public IEnumerable<IConfigurationTask> CreateInstallTasks()
        {
            yield return new InstallHl7MessageHandler(this, this.m_configuration);
        }

        /// <summary>
        /// Create uninstall tasks
        /// </summary>
        public IEnumerable<IConfigurationTask> CreateUninstallTasks()
        {
            yield return new UninstallHl7MessageHandler(this, this.m_configuration);
        }

        /// <summary>
        /// Query the feature state of this object
        /// </summary>
        public FeatureInstallState QueryState(SanteDBConfiguration configuration)
        {
            var hl7Config = this.m_configuration = configuration.GetSection<Hl7ConfigurationSection>();
            if(this.m_configuration == null)
            {
                this.m_configuration = new Hl7ConfigurationSection()
                {
                    BirthplaceClassKeys = new List<Guid>()
                    {
                        EntityClassKeys.State,
                        EntityClassKeys.PrecinctOrBorough,
                        EntityClassKeys.CityOrTown,
                        EntityClassKeys.ServiceDeliveryLocation,
                        EntityClassKeys.Country
                    },
                    LocalAuthority = new Core.Model.DataTypes.AssigningAuthority("YOUR_LOCAL_V2_AUTHORITY", "Local Authority", $"2.25.{BitConverter.ToInt64(Guid.NewGuid().ToByteArray(), 0)}"),
                    SsnAuthority = new Core.Model.DataTypes.AssigningAuthority("SSN", "Social Security Number", "2.16.840.1.113883.4.1"),
                    IdentifierReplacementBehavior = IdentifierReplacementMode.Specific,
                    LocalFacility = Guid.Empty,
                    Security = AuthenticationMethod.Msh8,
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

            // Application configuration section
            var appSection = configuration.GetSection<ApplicationServiceContextConfigurationSection>().ServiceProviders.Any(s=>s.Type == typeof(HL7MessageHandler));
            return appSection && hl7Config != null ? FeatureInstallState.Installed : hl7Config == null || !appSection ? FeatureInstallState.PartiallyInstalled : FeatureInstallState.NotInstalled;
        }
    }

    /// <summary>
    /// Remove the HL7 message handler from the configuration file
    /// </summary>
    internal class UninstallHl7MessageHandler : IConfigurationTask
    {

        // Configuration
        private Hl7ConfigurationSection m_configuration;

        /// <summary>
        /// Creates a new instance of the uninstallation task
        /// </summary>
        public UninstallHl7MessageHandler(IFeature hostFeature, Hl7ConfigurationSection configuration)
        {
            this.m_configuration = configuration;
            this.Feature = hostFeature;
        }

        /// <summary>
        /// Gets the description of this task
        /// </summary>
        public string Description => "Removes the HL7 message handler, and registers the HL7 message endpoints configured in the panel.";

           /// <summary>
           /// Gets the feature that hosts this task
           /// </summary>
        public IFeature Feature { get; }

        /// <summary>
        /// Gets the name of this feature
        /// </summary>
        public string Name => "Remove HL7 Messaging";

        /// <summary>
        /// Progress has changed
        /// </summary>
        public event EventHandler<ProgressChangedEventArgs> ProgressChanged;

        /// <summary>
        /// Execute the removal feature
        /// </summary>
        public bool Execute(SanteDBConfiguration configuration)
        {
            configuration.RemoveSection<Hl7ConfigurationSection>();
            configuration.GetSection<ApplicationServiceContextConfigurationSection>().ServiceProviders.RemoveAll(o => o.Type == typeof(HL7MessageHandler));
            return true;
        }

        /// <summary>
        /// Rollback the configuration setup
        /// </summary>
        public bool Rollback(SanteDBConfiguration configuration)
        {
            if (configuration.GetSection<Hl7ConfigurationSection>() == null)
            {
                configuration.AddSection(this.m_configuration);
            }
            var services = configuration.GetSection<ApplicationServiceContextConfigurationSection>().ServiceProviders;
            if(!services.Any(o=>o.Type == typeof(HL7MessageHandler)))
            {
                services.Add(new TypeReferenceConfiguration(typeof(HL7MessageHandler)));
            }
            return true;
        }

        /// <summary>
        /// Verify the state of this task
        /// </summary>
        public bool VerifyState(SanteDBConfiguration configuration) => configuration.GetSection<Hl7ConfigurationSection>() != null;
    }

    /// <summary>
    /// Represents a task that installs the HL7 messaging feature.
    /// </summary>
    internal class InstallHl7MessageHandler : IConfigurationTask
    {

        // Configuration section
        private Hl7ConfigurationSection m_configuration;

        /// <summary>
        /// Create a new installation feature
        /// </summary>
        public InstallHl7MessageHandler(IFeature hostFeature, Hl7ConfigurationSection configurationSection)
        {
            this.m_configuration = configurationSection;
            this.Feature = hostFeature;
        }

        /// <summary>
        /// Gets the description of this feature
        /// </summary>
        public string Description => "Installs the HL7 message receiver service into the configuration file, and registers the configuration settings provided in the panel";

        /// <summary>
        /// Gets the feature
        /// </summary>
        public IFeature Feature { get; }

        /// <summary>
        /// Gets the name of the feature
        /// </summary>
        public string Name => "Install HL7 Messaging";

        /// <summary>
        /// Progress has changed
        /// </summary>
        public event EventHandler<ProgressChangedEventArgs> ProgressChanged;

        /// <summary>
        /// Execute the installation 
        /// </summary>
        public bool Execute(SanteDBConfiguration configuration)
        {
            configuration.RemoveSection<Hl7ConfigurationSection>(); // remove the old
            configuration.AddSection(this.m_configuration);

            // Register the HL7 messaging service
            var services = configuration.GetSection<ApplicationServiceContextConfigurationSection>().ServiceProviders;
            if(!services.Any(s=>s.Type == typeof(HL7MessageHandler)))
            {
                services.Add(new TypeReferenceConfiguration(typeof(HL7MessageHandler)));
            }
            return true;
        }

        /// <summary>
        /// Rollback the configuration
        /// </summary>
        public bool Rollback(SanteDBConfiguration configuration)
        {
            configuration.RemoveSection<Hl7ConfigurationSection>();
            configuration.GetSection<ApplicationServiceContextConfigurationSection>().ServiceProviders.RemoveAll(o => o.Type == typeof(HL7MessageHandler));
            return true;
        }

        /// <summary>
        /// Verify this task can be executed
        /// </summary>
        public bool VerifyState(SanteDBConfiguration configuration) => true;
    }
}
