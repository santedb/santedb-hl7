using NHapi.Base;
using NHapi.Base.Model;
using NHapi.Base.Parser;
using NHapi.Model.V25.Message;
using NHapi.Model.V25.Segment;
using SanteDB.Core;
using SanteDB.Core.Diagnostics;
using SanteDB.Core.i18n;
using SanteDB.Core.Model;
using SanteDB.Core.Model.DataTypes;
using SanteDB.Core.Model.Entities;
using SanteDB.Core.Model.Roles;
using SanteDB.Core.PubSub;
using SanteDB.Core.Security;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.Client;
using SanteDB.Messaging.HL7.Configuration;
using SanteDB.Messaging.HL7.Segments;
using SanteDB.Messaging.HL7.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Hl7.Fhir.Model.VerificationResult;

namespace SanteDB.Messaging.HL7.PubSub
{
    /// <summary>
    /// Represnts a dispatcher factory which can send ADT messages as a
    /// patient identity source
    /// </summary>
    public class PatientIdentitySourceDIspatcherFactory : IPubSubDispatcherFactory
    {
        /// <inheritdoc/>
        public string Id => "hl7-pat-id-source";

        /// <inheritdoc/>
        public IEnumerable<string> Schemes => new[] { "hl7-pid-src-llp", "hl7-pid-src-sllp" };

        /// <inheritdoc/>
        public IPubSubDispatcher CreateDispatcher(Guid channelKey, Uri endpoint, IDictionary<string, string> settings)
        {
            return new Dispatcher(channelKey, endpoint, settings);
        }

        /// <summary>
        /// The dispatcher for HL7v2 LLP 
        /// </summary>
        public class Dispatcher : IPubSubDispatcher
        {

            public const string SETTING_SENDING_DEVICE = "SENDER";
            public const string SETTING_RECEIVER_DEVICE = "RECEIVER";
            public const string SETTING_SECRET = "SECRET";
            public const string SETTING_CERTIFICATE = "CLIENT_CERT";
            public const string SETTING_EXPORT_ID = "EXPORT_DOMAINS";

            private readonly string[] SUCCESS_CODES = new[] { "AA", "CA" };

            private readonly IdentityDomain[] m_exportDomains = null;

            private readonly Hl7ConfigurationSection m_configuation;

            /// <summary>
            /// Tracer
            /// </summary>
            private readonly Tracer m_tracer = Tracer.GetTracer(typeof(Dispatcher));

            /// <inheritdoc/>
            public Dispatcher(Guid channelKey, Uri endpoint, IDictionary<string, string> settings)
            {
                this.Key = channelKey;
                this.Endpoint = endpoint;
                this.Settings = settings;
                this.m_configuation = ApplicationServiceContext.Current.GetService<IConfigurationManager>().GetSection<Hl7ConfigurationSection>();

                if (settings.TryGetValue(SETTING_EXPORT_ID, out var domains))
                {
                    var domainService = ApplicationServiceContext.Current.GetService<IIdentityDomainRepositoryService>();
                    m_exportDomains = domains.Split(',').Select(o => domainService.Get(o)).OfType<IdentityDomain>().ToArray();
                }
            }

            /// <inheritdoc/>
            public Guid Key { get; }

            /// <inheritdoc/>
            public Uri Endpoint { get; }

            /// <inheritdoc/>
            public IDictionary<string, string> Settings { get; }

            /// <summary>
            /// Update the PID segment
            /// </summary>
            private void UpdatePID(IGroup group, Patient patient)
            {
                var pid = group.GetStructure("PID") as PID;
                // ensure authenticated
                using (AuthenticationContext.EnterSystemContext())
                {
                    
                    _ = new PIDSegmentHandler().Create(patient, group, m_exportDomains);
                    _ = new PD1SegmentHandler().Create(patient, group, m_exportDomains);
                }
            }

            /// <summary>
            /// Update the MSH header
            /// </summary>
            private void UpdateMSH(IMessage message)
            {
                var msh = message.GetStructure("MSH") as MSH;

                msh.AcceptAcknowledgmentType.Value = "AL";
                msh.DateTimeOfMessage.Time.Value = DateTime.Now.ToString("yyyyMMddHHmmss");
                msh.MessageControlID.Value = BitConverter.ToInt64(Guid.NewGuid().ToByteArray(), 0).ToString();
                msh.ProcessingID.ProcessingID.Value = "P";

                if (this.Settings.TryGetValue(SETTING_RECEIVER_DEVICE, out var setting) && setting.Contains("|"))
                {
                    msh.ReceivingApplication.NamespaceID.Value = setting.Split('|')[0];
                    msh.ReceivingFacility.NamespaceID.Value = setting.Split('|')[1];
                }
                else
                {
                    throw new InvalidOperationException($"Setting {SETTING_RECEIVER_DEVICE} is required in formation APPLICATION|FACILITY");
                }

                if (this.Settings.TryGetValue(SETTING_SECRET, out var secret))
                {
                    msh.Security.Value = secret;
                }

                // set MSH-3 as the NSID of the patient identifier
                if (this.Settings.TryGetValue(SETTING_SENDING_DEVICE, out var sender) && sender.Contains("|"))
                {
                    msh.SendingApplication.NamespaceID.Value = sender.Split('|')[0];
                    msh.SendingFacility.NamespaceID.Value = sender.Split('|')[1];
                }
                else
                {
                    throw new InvalidOperationException($"Setting {SETTING_RECEIVER_DEVICE} is required in formation APPLICATION|FACILITY");
                }
                msh.VersionID.VersionID.Value = "2.3.1";
            }

            /// <summary>
            /// Send the message
            /// </summary>
            private void Send(IMessage message)
            {
                try
                {
                    // TODO: Allow for configuration of a certificate sender
                    var certificateManager = X509CertificateUtils.GetPlatformServiceOrDefault();
                    X509Certificate2 certificate = null;
                    if (this.Settings.TryGetValue(SETTING_CERTIFICATE, out var x509FindValue) && 
                        (certificateManager.TryGetCertificate(X509FindType.FindBySubjectName, x509FindValue, out certificate) 
                        || certificateManager.TryGetCertificate(X509FindType.FindByThumbprint, x509FindValue, out certificate)))
                    {

                    }
                    var llpSender = new MllpMessageSender(this.Endpoint, certificate, null);

                    var pp = new PipeParser();
                    this.m_tracer.TraceInfo("Sending to {0} -> {1}", this.Endpoint, pp.Encode(message));
                    var response = llpSender.SendAndReceive(message);
                    this.m_tracer.TraceInfo("Received from {0} -> {1}", this.Endpoint, pp.Encode(response));

                    var isSuccess = response is NHapi.Model.V231.Message.ACK ack3 && SUCCESS_CODES.Contains(ack3.MSA.AcknowledgementCode.Value.ToUpper()) ||
                        response is NHapi.Model.V25.Message.ACK ack5 && SUCCESS_CODES.Contains(ack5.MSA.AcknowledgmentCode.Value.ToUpper());
                    if(!isSuccess)
                    {
                        throw new System.Net.ProtocolViolationException(ErrorMessages.MESSAGE_REJECTED);
                    }
                }
                catch(System.Net.ProtocolViolationException)
                {
                    throw;
                }
                catch(Exception e)
                {
                    throw new InvalidOperationException(ErrorMessages.GENERAL_NOTIFICATION_ERROR, e);
                }
            }

            /// <inheritdoc/>
            public void NotifyCreated<TModel>(TModel data) where TModel : IdentifiedData
            {
                if(data is Patient patient)
                {
                    var message = new ADT_A01();
                    this.UpdateMSH(message);
                    this.UpdatePID(message, patient);
                    this.Send(message);
                }
                else
                {
                    throw new ArgumentOutOfRangeException(ErrorMessages.ARGUMENT_INCOMPATIBLE_TYPE);
                }
            }

            /// <inheritdoc/>
            public void NotifyLinked<TModel>(TModel primary, TModel target) where TModel : IdentifiedData
            {
                if (primary is Patient primaryPatient && target is Patient linkedPatient)
                {
                    var message = new ADT_A39();
                    this.UpdateMSH(message);
                    var patientGroup = message.GetPATIENT();
                    this.UpdatePID(patientGroup, primaryPatient);
                    this.Send(message);
                }
                else
                {
                    throw new ArgumentOutOfRangeException(ErrorMessages.ARGUMENT_INCOMPATIBLE_TYPE);
                }
            }

            /// <inheritdoc/>
            public void NotifyMerged<TModel>(TModel survivor, IEnumerable<TModel> subsumed) where TModel : IdentifiedData
            {
                if (survivor is Patient primaryPatient)
                {
                    var message = new ADT_A39();
                    this.UpdateMSH(message);
                    foreach(var itm in subsumed)
                    {
                        var patientGroup = message.GetPATIENT(message.PATIENTRepetitionsUsed);
                        this.UpdatePID(patientGroup, primaryPatient);

                    }
                    this.Send(message);
                }
                else
                {
                    throw new ArgumentOutOfRangeException(ErrorMessages.ARGUMENT_INCOMPATIBLE_TYPE);
                }
            }

            /// <inheritdoc/>
            public void NotifyObsoleted<TModel>(TModel data) where TModel : IdentifiedData
            {
                this.m_tracer.TraceWarning("HL7v2 Patient Identity Feed does not support obsoletion notifications");
            }

            /// <inheritdoc/>
            public void NotifyUnlinked<TModel>(TModel holder, TModel target) where TModel : IdentifiedData
            {
                this.m_tracer.TraceWarning("HL7v2 Patient Identity Feed does not support unlink notifications");
            }

            /// <inheritdoc/>
            public void NotifyUnMerged<TModel>(TModel primary, IEnumerable<TModel> unMerged) where TModel : IdentifiedData
            {
                this.m_tracer.TraceWarning("HL7v2 Patient Identity Feed does not support unmerge notifications");
            }

            /// <inheritdoc/>
            public void NotifyUpdated<TModel>(TModel data) where TModel : IdentifiedData
            {
                if (data is Patient patient)
                {
                    var message = new ADT_A01();
                    message.MSH.MessageType.MessageCode.Value = "ADT";
                    message.MSH.MessageType.MessageStructure.Value = "ADT_A08";
                    message.MSH.MessageType.TriggerEvent.Value = "A08";
                    this.UpdateMSH(message);
                    this.UpdatePID(message, patient);
                    this.Send(message);
                }
                else
                {
                    throw new ArgumentOutOfRangeException(ErrorMessages.ARGUMENT_INCOMPATIBLE_TYPE);
                }
            }
        }

    }
}
