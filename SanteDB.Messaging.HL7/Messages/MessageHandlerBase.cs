/*
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
using NHapi.Base.Model;
using NHapi.Base.Parser;
using NHapi.Model.V25.Message;
using NHapi.Model.V25.Segment;
using SanteDB.Core;
using SanteDB.Core.Diagnostics;
using SanteDB.Core.Exceptions;
using SanteDB.Core.Model;
using SanteDB.Core.Model.Collection;
using SanteDB.Core.Security;
using SanteDB.Core.Security.Audit;
using SanteDB.Core.Security.Claims;
using SanteDB.Core.Security.Principal;
using SanteDB.Core.Security.Services;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.Configuration;
using SanteDB.Messaging.HL7.Exceptions;
using SanteDB.Messaging.HL7.TransportProtocol;
using SanteDB.Messaging.HL7.Utils;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics.Tracing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Authentication;
using System.Security.Principal;
using System.Xml;
#pragma warning disable CS0612

namespace SanteDB.Messaging.HL7.Messages
{
    /// <summary>
    /// Represents a message handler
    /// </summary>
    public abstract class MessageHandlerBase : IHL7MessageHandler, IServiceImplementation
    {
        // Configuration
        private Hl7ConfigurationSection m_configuration = ApplicationServiceContext.Current?.GetService<IConfigurationManager>().GetSection<Hl7ConfigurationSection>();

        /// <summary>
        /// The tracing source
        /// </summary>
        protected readonly Tracer m_traceSource = new Tracer(Hl7Constants.TraceSourceName);

        /// <summary>
        /// The localization service injected into the service instance
        /// </summary>
        protected readonly ILocalizationService m_localizationService;

        /// <summary>
        /// The auditing building service injected nto the service
        /// </summary>
        protected readonly IAuditService _AuditService;

        /// <summary>
        /// DI constructor
        /// </summary>
        public MessageHandlerBase(ILocalizationService localizationService, IAuditService auditService)
        {
            this.m_localizationService = localizationService;
            _AuditService = auditService;   
        }

        /// <summary>
        /// Get the supported triggers
        /// </summary>
        public abstract string[] SupportedTriggers { get; }

        /// <summary>
        /// Get the service name
        /// </summary>
        public string ServiceName => "Message Handler Base";

        /// <summary>
        /// Allows overridden classes to implement the message handling logic
        /// </summary>
        /// <param name="e">The message receive event args</param>
        /// <returns>The resulting message</returns>
        /// <param name="parsed">The parsed bundle</param>
        protected abstract IMessage HandleMessageInternal(Hl7MessageReceivedEventArgs e, Bundle parsed);

        /// <summary>
        /// Validate the specified message
        /// </summary>
        /// <param name="message">The message to be validated</param>
        /// <returns>True if the message is valid</returns>
        protected abstract bool Validate(IMessage message);

        /// <summary>
        /// Handle the message generic handler
        /// </summary>
        /// <param name="e">The message event information</param>
        /// <returns>The result of the message handling</returns>
        public virtual IMessage HandleMessage(Hl7MessageReceivedEventArgs e)
        {
            try
            {
                using (this.Authenticate(e))
                {
                    if (!this.Validate(e.Message))
                    {
                        this.m_traceSource.TraceError("Invalid message");
                        throw new ArgumentException(this.m_localizationService.GetString("error.messaging.hl7.invalidMessage"));
                    }

                    var bundle = MessageUtils.Parse(e.Message);
                    bundle.AddAnnotationToAll(SanteDBModelConstants.NoDynamicLoadAnnotation);
                    return this.HandleMessageInternal(e, bundle);
                }
            }
            catch (Exception ex)
            {
                this.m_traceSource.TraceEvent(EventLevel.Error, "Error processing message: {0}", ex);
                return this.CreateNACK(typeof(ACK), e.Message, ex, e);
            }
        }

        /// <summary>
        /// Authetnicate
        /// </summary>
        private IDisposable Authenticate(Hl7MessageReceivedEventArgs e)
        {
            IPrincipal principal = null;
            var msh = e.Message.GetStructure("MSH") as MSH;
            var sft = e.Message.GetStructure("SFT") as SFT;

            if (string.IsNullOrEmpty(msh.Security.Value) && this.m_configuration.Security == Hl7AuthenticationMethod.Msh8)
            {
                this.m_traceSource.TraceError("Must carry MSH-8 authorization token information");
                throw new SecurityException(this.m_localizationService.GetString("error.messaging.h17.authorizationToken"));
            }
            if (msh.Security.Value?.StartsWith("sid://") == true) // Session identifier
            {
                var sessiontokenresolver = ApplicationServiceContext.Current.GetService<ISessionTokenResolverService>();

                var sessionidentifier = msh.Security.Value.Substring("sid://".Length);

                var session = sessiontokenresolver.GetSessionFromIdToken(sessionidentifier);

                principal = ApplicationServiceContext.Current.GetService<ISessionIdentityProviderService>().Authenticate(session) as IClaimsPrincipal;
            }
            else if (e is AuthenticatedHl7MessageReceivedEventArgs auth && auth.AuthorizationToken != null)
            {
                // Ensure proper authentication exists
                if (String.IsNullOrEmpty(msh.SendingFacility.NamespaceID.Value))
                {
                    this.m_traceSource.TraceError("MSH-4 must be provided for authenticating device");
                    throw new SecurityException(this.m_localizationService.GetString("error.messaging.h17.authenticating", new
                    {
                        param = "MSH-4",
                        param2 = " device"
                    }));
                }
                else if (String.IsNullOrEmpty(msh.SendingApplication.NamespaceID.Value))
                {
                    this.m_traceSource.TraceError("MSH-3 must be provided for authenticating device/application");
                    throw new SecurityException(this.m_localizationService.GetString("error.messaging.h17.authenticating", new
                    {
                        param = "MSH-3",
                        param2 = " device/application"
                    }));
                }
                else if (this.m_configuration.Security == Hl7AuthenticationMethod.Sft4 && string.IsNullOrEmpty(sft.SoftwareBinaryID.Value))
                {
                    this.m_traceSource.TraceError("SFT-4 must be provided for authenticating application");
                    throw new SecurityException(this.m_localizationService.GetString("error.messaging.h17.authenticating", new
                    {
                        param = "SFT-4",
                        param2 = " application"
                    }));
                }
                else if (this.m_configuration.Security == Hl7AuthenticationMethod.Msh8 && string.IsNullOrEmpty(msh.Security.Value))
                {
                    this.m_traceSource.TraceError("MSH-8 must be provided for authenticating application");
                    throw new SecurityException(this.m_localizationService.GetString("error.messaging.h17.authenticating", new
                    {
                        param = "MSH-8",
                        param2 = " application"
                    }));
                }

                String applicationId = msh.SendingApplication.NamespaceID.Value, applicationSecret = null;

                switch (this.m_configuration.Security)
                {
                    case Hl7AuthenticationMethod.None: // No special - authenticate the app using device creds
                        applicationSecret = this.m_configuration.NoAuthenticationSecret;
                        break;

                    case Hl7AuthenticationMethod.Msh8:
                        applicationSecret = msh.Security.Value;
                        break;

                    case Hl7AuthenticationMethod.Sft4:
                        applicationSecret = sft.SoftwareBinaryID.Value;
                        break;

                    default:
                        throw new InvalidOperationException("Unknown Security Method Configured");
                }

                IPrincipal certificatePrincipal = ApplicationServiceContext.Current.GetService<ICertificateIdentityProvider>()?.Authenticate(auth.AuthorizationToken);

                if (certificatePrincipal == null)
                {
                    throw new InvalidOperationException("In order to use node authentication with X509 certificates - there must be a CertificateIdentityProvider configured");
                }
                else if (certificatePrincipal.Identity is IApplicationIdentity)
                {
                    principal = certificatePrincipal;
                }
                else
                {
                    var applicationPrincipal = applicationSecret != null ? ApplicationServiceContext.Current.GetService<IApplicationIdentityProviderService>()?.Authenticate(applicationId, applicationSecret) : null;
                    if (applicationPrincipal == null && this.m_configuration.RequireAuthenticatedApplication)
                    {
                        this.m_traceSource.TraceError("Server requires authenticated application");
                        throw new UnauthorizedAccessException(this.m_localizationService.GetString("error.type.UnauthorizedAccessException"));
                    }
                    principal = new SanteDBClaimsPrincipal(new IIdentity[] { certificatePrincipal.Identity, applicationPrincipal?.Identity }.OfType<IClaimsIdentity>());
                }
            }
            else if (this.m_configuration.Security != Hl7AuthenticationMethod.None)
            {
                // Ensure proper authentication exists
                if (string.IsNullOrEmpty(msh.SendingFacility.NamespaceID.Value) || string.IsNullOrEmpty(msh.Security.Value))
                {
                    this.m_traceSource.TraceError("MSH-4 and MSH-8 must always be provided for authenticating device when SLLP is not used");
                    throw new SecurityException(this.m_localizationService.GetString("error.messaging.hl7.sllpNotUsed"));
                }
                else if (string.IsNullOrEmpty(msh.SendingFacility.NamespaceID.Value))
                {
                    this.m_traceSource.TraceError("MSH-3 must be provided for authenticating application");
                    throw new SecurityException(this.m_localizationService.GetString("error.messaging.h17.authenticating", new
                    {
                        param = "MSH-3",
                        param2 = "application"
                    }));
                }
                else if (this.m_configuration.Security == Hl7AuthenticationMethod.Sft4 && string.IsNullOrEmpty(sft.SoftwareBinaryID.Value))
                {
                    this.m_traceSource.TraceError("SFT-4 must be provided for authenticating application");
                    throw new SecurityException(this.m_localizationService.GetString("error.messaging.h17.authenticating", new
                    {
                        param = "SFT-4",
                        param2 = "application"
                    }));
                }
                else if (this.m_configuration.Security == Hl7AuthenticationMethod.Msh8 && string.IsNullOrEmpty(msh.Security.Value))
                {
                    this.m_traceSource.TraceError("MSH-8 must be provided for authenticating application");

                    throw new SecurityException(this.m_localizationService.GetString("error.messaging.h17.authenticating", new
                    {
                        param = "MSH-8",
                        param2 = "application"
                    }));
                }
                String deviceId = $"{msh.SendingApplication.NamespaceID.Value}|{msh.SendingFacility.NamespaceID.Value}",
                   deviceSecret = msh.Security.Value,
                   applicationId = msh.SendingApplication.NamespaceID.Value,
                   applicationSecret = this.m_configuration.Security == Hl7AuthenticationMethod.Sft4 ? sft.SoftwareBinaryID.Value :
                                            this.m_configuration.Security == Hl7AuthenticationMethod.Msh8 ? msh.Security.Value : null;

                if (applicationSecret == deviceSecret && applicationSecret.Contains("+")) // Both device and app are using same auth key? Odd, perhaps there is the delimeter
                {
                    var secrets = applicationSecret.Split('+');
                    applicationSecret = secrets[1]; deviceSecret = secrets[0];
                }
                else
                {
                    applicationSecret = this.m_configuration.NoAuthenticationSecret;
                }

                IPrincipal devicePrincipal = ApplicationServiceContext.Current.GetService<IDeviceIdentityProviderService>().Authenticate(deviceId, deviceSecret, AuthenticationMethod.Local),
                    applicationPrincipal = applicationSecret != null ? ApplicationServiceContext.Current.GetService<IApplicationIdentityProviderService>()?.Authenticate(applicationId, applicationSecret) : null;

                if (applicationPrincipal == null && this.m_configuration.RequireAuthenticatedApplication)
                {
                    this.m_traceSource.TraceError("Server requires authenticated application");
                    throw new UnauthorizedAccessException(this.m_localizationService.GetString("error.type.UnauthorizedAccessException"));
                }

                principal = new SanteDBClaimsPrincipal((new IIdentity[] { devicePrincipal.Identity, applicationPrincipal?.Identity }).OfType<IClaimsIdentity>());
            }
            else
            {
                principal = ApplicationServiceContext.Current.GetService<IApplicationIdentityProviderService>().Authenticate(msh.SendingApplication.NamespaceID.Value, this.m_configuration.NoAuthenticationSecret);
            }

            // Clear authentication cache for principal (NB: we're doing this because we're not establishing a session)
            ApplicationServiceContext.Current.GetService<IPolicyDecisionService>().ClearCache(principal);

            // Pricipal
            if (principal != null)
            {
                return AuthenticationContext.EnterContext(principal);
            }

            return AuthenticationContext.EnterContext(AuthenticationContext.AnonymousPrincipal);
        }

        /// <summary>
        /// Map detail to error code
        /// </summary>
        private string MapErrCode(Exception error)
        {
            string errCode = string.Empty;
            var e = error;

            while (e != null)
            {
                if (e is ConstraintException)
                {
                    errCode = "101";
                }
                else if (e is HL7DatatypeProcessingException)
                {
                    errCode = "102";
                }
                else if (e is HL7ProcessingException)
                {
                    errCode = "199";
                }
                else if (e is DuplicateNameException)
                {
                    errCode = "205";
                }
                else if (e is DataException || e is DetectedIssueException)
                {
                    errCode = "207";
                }
                else if (e is VersionNotFoundException)
                {
                    errCode = "203";
                }
                else if (e is NotImplementedException)
                {
                    errCode = "200";
                }
                else if (e is KeyNotFoundException || e is FileNotFoundException)
                {
                    errCode = "204";
                }
                else if (e is SecurityException)
                {
                    errCode = "901";
                }

                e = e.InnerException;
            }

            if (String.IsNullOrEmpty(errCode))
            {
                errCode = "207";
            }

            return errCode;
        }

        /// <summary>
        /// Create a negative acknolwedgement from the specified exception
        /// </summary>
        /// <param name="request">The request message</param>
        /// <param name="error">The exception that occurred</param>
        /// <returns>NACK message</returns>
        /// <param name="nackType">The type of NACK message to construct</param>
        /// <param name="receiveData">The data which was received (for correlation on the NACL)</param>
        protected virtual IMessage CreateNACK(Type nackType, IMessage request, Exception error, Hl7MessageReceivedEventArgs receiveData)
        {
            // Extract TIE into real cause
            while (error is TargetInvocationException)
            {
                error = error.InnerException;
            }

            var rootCause = error;
            while (rootCause.InnerException != null)
            {
                rootCause = rootCause.InnerException;
            }

            IMessage retVal = null;
            switch (rootCause)
            {
                case DomainStateException dse:
                    retVal = this.CreateACK(nackType, request, "AR", "Domain Error");
                    break;
                case PolicyViolationException pve:
                case SecurityException se:
                    retVal = this.CreateACK(nackType, request, "AR", "Security Error");
                    break;
                case AuthenticationException ae:
                case UnauthorizedAccessException uae:
                    retVal = this.CreateACK(nackType, request, "AR", "Unauthorized");
                    break;
                case JsonException je:
                case XmlException xe:
                    retVal = this.CreateACK(nackType, request, "AR", "Messaging Error");
                    break;
                case DuplicateNameException dne:
                    retVal = this.CreateACK(nackType, request, "CR", "Duplicate Data");
                    break;
                case FileNotFoundException fnfe:
                case KeyNotFoundException knfe:
                    retVal = this.CreateACK(nackType, request, "CE", "Data not found");
                    break;
                case DetectedIssueException die:
                    retVal = this.CreateACK(nackType, request, "CR", "Business Rule Violation");
                    break;
                case DataPersistenceException dpe:
                    retVal = this.CreateACK(nackType, request, "CE", "Error committing data");
                    break;
                case NotImplementedException nie:
                    retVal = this.CreateACK(nackType, request, "AR", "Not Implemented");
                    break;
                case NotSupportedException nse:
                    retVal = this.CreateACK(nackType, request, "AR", "Not Supported");
                    break;
                case HL7ProcessingException hlpe:
                case HL7DatatypeProcessingException hdpe:
                    retVal = this.CreateACK(nackType, request, "AE", "Invalid Message");
                    break;
                default:
                    retVal = this.CreateACK(nackType, request, "AR", "General Error");
                    break;
            }

            var msa = retVal.GetStructure("MSA") as MSA;
            msa.ErrorCondition.Identifier.Value = this.MapErrCode(error);
            msa.ErrorCondition.Text.Value = error.Message;

            int erc = 0;
            // Detected issue exception
            if (rootCause is DetectedIssueException dte)
            {
                foreach (var itm in dte.Issues)
                {
                    var err = retVal.GetStructure("ERR", erc) as ERR;
                    if (retVal.IsRepeating("ERR"))
                    {
                        erc++;
                    }

                    err.HL7ErrorCode.Identifier.Value = "207";
                    err.Severity.Value = itm.Priority == Core.BusinessRules.DetectedIssuePriorityType.Error ? "E" : itm.Priority == Core.BusinessRules.DetectedIssuePriorityType.Warning ? "W" : "I";
                    err.GetErrorCodeAndLocation(err.ErrorCodeAndLocationRepetitionsUsed).CodeIdentifyingError.Text.Value = itm.Text;
                }
            }
            else
            {
                var ex = error;
                while (ex != null)
                {
                    var err = retVal.GetStructure("ERR", erc) as ERR;
                    if (retVal.IsRepeating("ERR"))
                    {
                        erc++;
                    }

                    err.HL7ErrorCode.Identifier.Value = this.MapErrCode(ex);
                    err.Severity.Value = "E";
                    err.GetErrorCodeAndLocation(err.ErrorCodeAndLocationRepetitionsUsed).CodeIdentifyingError.Text.Value = ex.Message;
                    if (ex is HL7ProcessingException hle)
                    {
                        var erl = err.GetErrorLocation(err.ErrorLocationRepetitionsUsed);
                        erl.SegmentID.Value = hle.Segment;
                        erl.SegmentSequence.Value = hle.Repetition ?? "1";
                        erl.FieldPosition.Value = hle.Field.ToString();
                        erl.FieldRepetition.Value = "1";
                        erl.ComponentNumber.Value = hle.Component.ToString();

                        var ihle = (hle.InnerException as HL7DatatypeProcessingException)?.InnerException as HL7DatatypeProcessingException; // Nested DTE
                        if (ihle != null)
                        {
                            erl.SubComponentNumber.Value = ihle.Component.ToString();
                        }
                    }

                    ex = ex.InnerException;
                }
            }

            var icomps = PipeParser.Encode(request.GetStructure("MSH") as MSH, new EncodingCharacters('|', "^~\\&")).Split('|');
            var ocomps = PipeParser.Encode(retVal.GetStructure("MSH") as MSH, new EncodingCharacters('|', "^~\\&")).Split('|');

            _AuditService.Audit().ForNetworkRequestFailure(error, receiveData.ReceiveEndpoint,
                Enumerable.Range(1, icomps.Length).ToDictionary(o => $"MSH-{o}", o => icomps[o - 1]),
                Enumerable.Range(1, ocomps.Length).ToDictionary(o => $"MSA-{o}", o => ocomps[o - 1])).Send();

            return retVal;
        }

        /// <summary>
        /// Create an acknowledge message
        /// </summary>
        /// <param name="request">The request which triggered this</param>
        /// <param name="ackCode">The acknowledgemode code</param>
        /// <param name="ackMessage">The message to append to the ACK</param>
        /// <param name="ackType">The acknowledgement type</param>
        protected virtual IMessage CreateACK(Type ackType, IMessage request, String ackCode, String ackMessage)
        {
            var retVal = Activator.CreateInstance(ackType) as IMessage;
            (retVal.GetStructure("MSH") as MSH).SetDefault(request.GetStructure("MSH") as MSH);
            if ((request.GetStructure("MSH") as MSH).VersionID.VersionID.Value == "2.5")
            {
                (retVal.GetStructure("SFT") as SFT).SetDefault();
            }

            var msa = retVal.GetStructure("MSA") as MSA;
            msa.MessageControlID.Value = (request.GetStructure("MSH") as MSH).MessageControlID.Value;
            msa.AcknowledgmentCode.Value = ackCode;
            msa.TextMessage.Value = ackMessage;

            // FAST ACK carry same response message type as request
            if (retVal is ACK ack)
            {
                ack.MSH.MessageType.MessageStructure.Value = ack.MSH.MessageType.MessageCode.Value = "ACK";
                ack.MSH.MessageType.TriggerEvent.Value = ack.MSH.MessageType.TriggerEvent.Value = "A01";
            }

            return retVal;
        }
    }
}
#pragma warning restore