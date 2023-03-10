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
using NHapi.Base.Model;
using NHapi.Model.V25.Message;
using NHapi.Model.V25.Segment;
using SanteDB.Core;
using SanteDB.Core.Model;
using SanteDB.Core.Model.Audit;
using SanteDB.Core.Model.Collection;
using SanteDB.Core.Model.Entities;
using SanteDB.Core.Model.Roles;
using SanteDB.Core.Security.Audit;
using SanteDB.Core.Security.Services;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.Exceptions;
using SanteDB.Messaging.HL7.TransportProtocol;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

namespace SanteDB.Messaging.HL7.Messages
{
    /// <summary>
    /// Represents a message handler that handles ADT messages
    /// </summary>
    [DisplayName("SanteDB ADT Message Handler")]
    public class AdtMessageHandler : MessageHandlerBase
    {
        // V2 focal object
        private const string V2_FOCAL = "$v2.pid";

        // Merging service
        private readonly IRecordMergingService<Patient> m_mergeService;

        // Bundle service
        private readonly IRepositoryService<Bundle> m_bundleService;

        /// <summary>
        /// DI constructor
        /// </summary>
        public AdtMessageHandler(ILocalizationService localizationService, IRecordMergingService<Patient> mergeService, IRepositoryService<Bundle> bundleService, IAuditService auditService) : base(localizationService, auditService)
        {
            this.m_mergeService = mergeService;
            this.m_bundleService = bundleService;
        }

        /// <summary>
        /// Supported triggers
        /// </summary>
        public override string[] SupportedTriggers => new string[] { "ADT^A01", "ADT^A04", "ADT^A08", "ADT^A40" };

        /// <summary>
        /// Handle the message internally
        /// </summary>
        /// <param name="e">The message receive events</param>
        /// <param name="parsed">The parsed message</param>
        /// <returns>The response to the ADT message</returns>
        protected override IMessage HandleMessageInternal(Hl7MessageReceivedEventArgs e, Bundle parsed)
        {
            var msh = e.Message.GetStructure("MSH") as MSH;
            switch (msh.MessageType.TriggerEvent.Value)
            {
                case "A01": // Admit
                case "A04": // Register
                    return this.PerformAdmit(e, parsed); // parsed.Item.OfType<Patient>().SingleOrDefault(o=>o.Tags.Any(t=>t.TagKey == ".v2.segment" && t.Value == "PID")));
                case "A08": // Update
                    return this.PerformUpdate(e, parsed);

                case "A40": // Merge
                    return this.PerformMerge(e, parsed);

                default:
                    this.m_traceSource.TraceError($"Do not understand event {msh.MessageType.TriggerEvent.Value}");
                    throw new InvalidOperationException(this.m_localizationService.GetString("error.type.InvalidOperation.eventNotUnderstood", new
                    {
                        param = msh.MessageType.TriggerEvent.Value
                    }));
            }
        }

        /// <summary>
        /// Perform an admission operation
        /// </summary>
        protected virtual IMessage PerformAdmit(Hl7MessageReceivedEventArgs e, Bundle insertBundle)
        {
            try
            {
                var patient = insertBundle.Item.OfType<Patient>().FirstOrDefault(it => it.Tags.Any(t => t.TagKey == "$v2.segment" && t.Value == "PID"));
                patient.AddAnnotation(V2_FOCAL);
                if (patient == null)
                {
                    this.m_traceSource.TraceError("Message did not contain a patient");
                    throw new ArgumentNullException(nameof(insertBundle), this.m_localizationService.GetString("error.type.ArgumentNullException.missingPatient"));
                }

                insertBundle = this.m_bundleService.Insert(insertBundle);

                this.SendAuditAdmit(OutcomeIndicator.Success, e.Message, insertBundle.Item.OfType<IdentifiedData>());

                // Create response message
                return this.CreateACK(typeof(ACK), e.Message, "CA", $"{String.Join(",", insertBundle.Item.OfType<Entity>().Select(o=>$"{o.BatchOperation} {o.Type}/{o.Key}"))}");
            }
            catch (Exception ex)
            {
                this.SendAuditAdmit(OutcomeIndicator.EpicFail, e.Message, null);
                this.m_traceSource.TraceError("Error performing admit");
                throw new HL7ProcessingException(this.m_localizationService.GetString("error.messaging.hl7.messages.errorPerformingAdmit"), null, null, 0, 0, ex);
            }
        }

        /// <summary>
        /// Send an audit of admit
        /// </summary>
        protected virtual void SendAuditAdmit(OutcomeIndicator outcomeIndicator, IMessage message, IEnumerable<IdentifiedData> results)
        {
            _AuditService.Audit().ForCreate(outcomeIndicator, null, results?.ToArray()).Send();
        }

        /// <summary>
        /// Perform an update of the specified patient
        /// </summary>
        protected virtual IMessage PerformUpdate(Hl7MessageReceivedEventArgs e, Bundle updateBundle)
        {
            try
            {
                var patient = updateBundle.Item.OfType<Patient>().FirstOrDefault(it => it.Tags.Any(t => t.TagKey == "$v2.segment" && t.Value == "PID"));
                if (patient == null)
                {
                    this.m_traceSource.TraceError("Message did not contain a patient");
                    throw new ArgumentNullException(nameof(updateBundle), this.m_localizationService.GetString("error.type.ArgumentNullException.missingPatient"));
                }
                else if (!patient.Key.HasValue)
                {
                    throw new InvalidOperationException("Update can only be performed on existing patients. Ensure that a unique identifier exists on the update record");
                }

                updateBundle = this.m_bundleService.Save(updateBundle);

                this.SendAuditUpdate(OutcomeIndicator.Success, e.Message, updateBundle.Item.ToArray());

                // Create response message
                return this.CreateACK(typeof(ACK), e.Message, "CA", $"{patient.Key} updated");
            }
            catch (Exception ex)
            {
                this.SendAuditUpdate(OutcomeIndicator.MinorFail, e.Message, updateBundle.Item.ToArray());
                throw new HL7ProcessingException(this.m_localizationService.GetString("error.messaging.hl7.messages.errorPerformingAdmit"), null, null, 0, 0, ex);
            }
        }

        /// <summary>
        /// Send audit update
        /// </summary>
        protected virtual void SendAuditUpdate(OutcomeIndicator outcome, IMessage message, IEnumerable<IdentifiedData> results)
        {
            _AuditService.Audit().ForUpdate(outcome, null, results?.ToArray()).Send();
        }

        /// <summary>
        /// Performs a merge of the specified patient
        /// </summary>
        protected virtual IMessage PerformMerge(Hl7MessageReceivedEventArgs e, Bundle bundle)
        {
            // A merge should be parsed as a series of bundles within bundles representing the merge pairs...
            try
            {
                var mergePairs = bundle.Item.OfType<Bundle>();
                if (!mergePairs.Any())
                {
                    this.m_traceSource.TraceError("Merge requires at least one pair of PID and MRG");
                    throw new InvalidOperationException(this.m_localizationService.GetString("error.messaging.hl7.messages.mergeMissingPair"));
                }

                foreach (var mrgPair in mergePairs)
                { 
                    var survivor = mrgPair.Item.OfType<Patient>().FirstOrDefault(o => o.GetTag("$v2.segment") == "PID");
                    var victims = mrgPair.Item.OfType<Patient>().Where(o => o.GetTag("$v2.segment") == "MRG");
                    try
                    {
                        if (survivor == null || !victims.Any())
                        {
                            this.m_traceSource.TraceError("Merge requires at least one pair of PID and MRG");
                            throw new InvalidOperationException(this.m_localizationService.GetString("error.messaging.hl7.messages.mergeMissingPair"));
                        }

                        // Perform the merge
                        this.SendAuditMerge(OutcomeIndicator.Success, e.Message, this.m_mergeService.Merge(survivor.Key.Value, victims.Select(o => o.Key.Value)));
                    }
                    catch (Exception ex)
                    {
                        this.SendAuditMerge(OutcomeIndicator.MinorFail, e.Message, new RecordMergeResult(RecordMergeStatus.Aborted, new Guid[] { survivor.Key.Value }, victims.Select(o=>o.Key.Value).ToArray()));
                        throw new HL7ProcessingException(this.m_localizationService.GetString("error.messaging.hl7.messages.errorPerformingMerge"), null, null, 0, 0, ex);
                    }
                }

                return this.CreateACK(typeof(ACK), e.Message, "CA", $"Merge accepted");
            }
            catch (HL7ProcessingException)
            {
                throw;
            }
            catch (Exception ex)
            {
                this.SendAuditMerge(OutcomeIndicator.SeriousFail, e.Message, null);
                throw new HL7ProcessingException(this.m_localizationService.GetString("error.messaging.hl7.messages.errorPerformingMerge"), null, null, 0, 0, ex);
            }
            throw new NotImplementedException(this.m_localizationService.GetString("error.type.NotImplementedException"));
        }

        /// <summary>
        /// Send audit merge
        /// </summary>
        protected virtual void SendAuditMerge(OutcomeIndicator outcome, IMessage message, RecordMergeResult recordMergeResult)
        {
            if (recordMergeResult != null)
            {
                _AuditService.Audit().ForDelete(outcome, "ADT^A40", new Patient() { Key = recordMergeResult.Replaced.First() }).Send();
                _AuditService.Audit().ForUpdate(outcome, "ADT^A40", new Patient() { Key = recordMergeResult.Survivors.First() }).Send();
            }
            else
            {
                _AuditService.Audit().ForUpdate<IdentifiedData>(outcome, "ADT^A40").Send();
            }
        }

        /// <summary>
        /// Validate the incoming message
        /// </summary>
        /// <param name="message">The message to be validated</param>
        /// <returns>The validated message</returns>
        protected override bool Validate(IMessage message)
        {
            return true;
        }
    }
}