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

using NHapi.Base.Model;
using NHapi.Base.Util;
using NHapi.Model.V25.Datatype;
using NHapi.Model.V25.Message;
using NHapi.Model.V25.Segment;
using SanteDB.Core;
using SanteDB.Core.Model.DataTypes;
using SanteDB.Core.Model.Query;
using SanteDB.Core.Model.Roles;
using SanteDB.Core.Security;
using SanteDB.Core.Services;
using SanteDB.Core.Matching;
using SanteDB.Messaging.HL7.Configuration;
using SanteDB.Messaging.HL7.Exceptions;
using SanteDB.Messaging.HL7.ParameterMap;
using SanteDB.Messaging.HL7.Segments;
using SanteDB.Messaging.HL7.TransportProtocol;
using SanteDB.Messaging.HL7.Utils;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using SanteDB.Core.Diagnostics;

namespace SanteDB.Messaging.HL7.Query
{
    /// <summary>
    /// Query result handler
    /// </summary>
    public class FindCandidatesQueryHandler : IQueryHandler, IServiceImplementation
    {
        // Configuration
        private Hl7ConfigurationSection m_configuration;

        private readonly ILocalizationService m_localizationService;
        private readonly IQueryScoringService m_scoringService;
        private readonly Tracer m_tracer = Tracer.GetTracer(typeof(FindCandidatesQueryHandler));

        /// <summary>
        /// Get the service name
        /// </summary>
        public string ServiceName => "Find Candidates Query Handler";

        /// <summary>
        /// Find candidates handler
        /// </summary>
        public FindCandidatesQueryHandler(IConfigurationManager configurationManager, ILocalizationService localizationService, IQueryScoringService queryScoringService = null)
        {
            this.m_localizationService = localizationService;
            this.m_configuration = configurationManager.GetSection<Hl7ConfigurationSection>();
            this.m_scoringService = queryScoringService;
        }

        /// <summary>
        /// Append query results to the message
        /// </summary>
        public virtual IMessage AppendQueryResult(IEnumerable results, Expression queryDefinition, IMessage currentResponse, Hl7MessageReceivedEventArgs evt, int offset = 0)
        {
            var patients = results.OfType<Patient>();
            if (patients.Count() == 0) return currentResponse;
            var retVal = currentResponse as RSP_K21;

            var pidHandler = SegmentHandlers.GetSegmentHandler("PID");
            var pd1Handler = SegmentHandlers.GetSegmentHandler("PD1");
            var nokHandler = SegmentHandlers.GetSegmentHandler("NK1");

            var matchService = ApplicationServiceContext.Current.GetService<IRecordMatchingService>();
            var matchConfigService = ApplicationServiceContext.Current.GetService<IRecordMatchingConfigurationService>();

            // Return domains
            var rqo = evt.Message as QBP_Q21;
            List<IdentityDomain> returnDomains = new List<IdentityDomain>();
            foreach (var rt in rqo.QPD.GetField(8).OfType<Varies>())
            {
                var rid = new CX(rqo.Message);
                DeepCopy.Copy(rt.Data as GenericComposite, rid);
                var authority = rid.AssigningAuthority.ToModel();
                returnDomains.Add(authority);
            }
            if (returnDomains.Count == 0)
                returnDomains = null;

            // Process results
            int i = offset + 1;
            IEnumerable<dynamic> resultScores = patients.Select(o => new { Patient = o, WasScored = false });
            if (this.m_scoringService != null)
            {
                resultScores = this.m_scoringService.Score<Patient>(queryDefinition as Expression<Func<Patient, bool>>, patients).Select(o => new
                {
                    Patient = o.Result,
                    Score = o.Score,
                    Method = o.Method,
                    WasScored = true
                });
            }

            foreach (var itm in resultScores)
            {
                var queryInstance = retVal.GetQUERY_RESPONSE(retVal.QUERY_RESPONSERepetitionsUsed);

                pidHandler.Create(itm.Patient, queryInstance, returnDomains?.ToArray());
                pd1Handler.Create(itm.Patient, queryInstance, null);
                nokHandler.Create(itm.Patient, queryInstance, null);
                queryInstance.PID.SetIDPID.Value = (i++).ToString();

                if (itm.WasScored)
                {
                    queryInstance.QRI.CandidateConfidence.Value = itm.Score.ToString();
                    switch ((RecordMatchMethod)itm.Method)
                    {
                        case RecordMatchMethod.Identifier:
                            queryInstance.QRI.GetMatchReasonCode(0).Value = "SS";
                            break;

                        case RecordMatchMethod.Simple:
                            queryInstance.QRI.GetMatchReasonCode(0).Value = "NA";
                            break;

                        case RecordMatchMethod.Weighted:
                            queryInstance.QRI.GetMatchReasonCode(0).Value = "NP";
                            break;
                    }
                    queryInstance.QRI.AlgorithmDescriptor.Identifier.Value = this.m_scoringService.ServiceName;
                }
                else
                {
                    queryInstance.QRI.CandidateConfidence.Value = "1.0";
                    queryInstance.QRI.AlgorithmDescriptor.Identifier.Value = "PTNM";
                }
            }

            return retVal;
        }

        /// <summary>
        /// Rewrite a QPD query to an HDSI query
        /// </summary>
        public virtual NameValueCollection ParseQuery(QPD qpd, Hl7QueryParameterType map)
        {
            NameValueCollection retVal = new NameValueCollection();

            // Control of strength
            String strStrength = (qpd.GetField(4, 0) as Varies)?.Data.ToString(),
                algorithm = (qpd.GetField(5, 0) as Varies)?.Data.ToString();
            Double? strength = String.IsNullOrEmpty(strStrength) ? null : (double?)Double.Parse(strStrength);

            // Query parameters
            foreach (var itm in MessageUtils.ParseQueryElement(qpd.GetField(3).OfType<Varies>(), map, algorithm, strength))
                try
                {
                    retVal.Add(itm.Key, itm.Value);
                }
                catch (Exception e)
                {
                    this.m_tracer.TraceError("Error processing query parameter", "QPD", "1", 3, 0, e);
                    throw new HL7ProcessingException(this.m_localizationService.GetString("error.type.HL7ProcessingException", new
                    {
                        param = "query parameter"
                    }), "QPD", "1", 3, 0, e);
                }

            // Return domains
            foreach (var rt in qpd.GetField(8).OfType<Varies>())
            {
                try
                {
                    var rid = new CX(qpd.Message);
                    DeepCopy.Copy(rt.Data as GenericComposite, rid);
                    var authority = rid.AssigningAuthority.ToModel();

                    if (authority.Key == this.m_configuration.LocalAuthority.Key)
                        retVal.Add("_id", rid.IDNumber.Value);
                    else
                        retVal.Add($"identifier[{authority.DomainName}]", "!null");
                }
                catch (Exception e)
                {
                    this.m_tracer.TraceError("Error processing return domains", "QPD", "1", 8, 0, e);
                    throw new HL7ProcessingException(this.m_localizationService.GetString("error.type.HL7ProcessingException", new
                    {
                        param = "return domains"
                    }), "QPD", "1", 8, 0, e);
                }
            }

            retVal.Add("obsoletionTime", "null");

            return retVal;
        }
    }
}