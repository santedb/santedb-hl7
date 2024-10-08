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
using NHapi.Base.Model;
using NHapi.Base.Parser;
using NHapi.Base.Util;
using NHapi.Model.V25.Segment;
using SanteDB.Core;
using SanteDB.Core.Diagnostics;
using SanteDB.Core.Model;
using SanteDB.Core.Model.Audit;
using SanteDB.Core.Model.Collection;
using SanteDB.Core.Model.Query;
using SanteDB.Core.Model.Serialization;
using SanteDB.Core.Security.Audit;
using SanteDB.Core.Security.Services;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.ParameterMap;
using SanteDB.Messaging.HL7.TransportProtocol;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.Tracing;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Xml.Serialization;
#pragma warning disable CS0612

namespace SanteDB.Messaging.HL7.Messages
{
    /// <summary>
    /// Query by parameter messge handler
    /// </summary>
    [DisplayName("SanteDB QBP Message Handler")]
    public class QbpMessageHandler : MessageHandlerBase
    {
        // Loaded query parameter map
        private static Hl7QueryParameterMap s_map;

        /// <summary>
        /// DI constructor
        /// </summary>
        /// <param name="localizationService"></param>
        /// <param name="auditService"></param>
        public QbpMessageHandler(ILocalizationService localizationService, IAuditService auditService) : base(localizationService, auditService)
        {
        }

        /// <summary>
        /// Diagnostic tracer
        /// </summary>
        protected static readonly Tracer m_tracer = Tracer.GetTracer(typeof(QbpMessageHandler));

        /// <summary>
        /// Gets the supported triggers
        /// </summary>
        public override string[] SupportedTriggers => s_map.Map.Select(o => $"QBP^{o.Trigger}").ToArray();

        /// <summary>
        /// Qbp Message handler CTOR
        /// </summary>
        static QbpMessageHandler()
        {
            OpenMapping(typeof(QbpMessageHandler).Assembly.GetManifestResourceStream("SanteDB.Messaging.HL7.ParameterMap.xml"));

            if (!String.IsNullOrEmpty(Assembly.GetEntryAssembly()?.Location))
            {
                var externMap = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "ParameterMap.Hl7.xml");

                if (File.Exists(externMap))
                {
                    using (var s = File.OpenRead(externMap))
                    {
                        OpenMapping(s);
                    }
                }
            }
        }

        /// <summary>
        /// Open the specified mapping
        /// </summary>
        private static void OpenMapping(Stream stream)
        {
            XmlSerializer xsz = XmlModelSerializerFactory.Current.CreateSerializer(typeof(Hl7QueryParameterMap));

            if (s_map == null)
            {
                s_map = xsz.Deserialize(stream) as Hl7QueryParameterMap;
            }
            else
            {
                // Merge
                var map = xsz.Deserialize(stream) as Hl7QueryParameterMap;
                s_map.Merge(map);
            }
        }

        /// <summary>
        /// Get the specified mapping for the specified trigger
        /// </summary>
        /// <param name="triggerEvent">The trigger event</param>
        /// <remarks>Allows overides to change the IQueryHandler and query parameter mapping</remarks>
        protected virtual Hl7QueryParameterType GetMapping(String triggerEvent)
        {
            return s_map.Map.First(o => o.Trigger == triggerEvent);
        }

        /// <summary>
        /// Handle message internally
        /// </summary>
        protected override IMessage HandleMessageInternal(Hl7MessageReceivedEventArgs e, Bundle parsed)
        {
            // First we want to get the map
            var msh = e.Message.GetStructure("MSH") as MSH;
            var trigger = msh.MessageType.TriggerEvent.Value;
            var map = this.GetMapping(trigger);
            var qpd = e.Message.GetStructure("QPD") as QPD;
            try
            {
                if (map.ResponseType == null)
                {
                    m_traceSource.TraceError($"Response type not found");
                    throw new NotSupportedException(m_localizationService.GetString("error.messaging.hl7.responseType"));
                }
                // First, process the query parameters
                var query = map.QueryHandler.ParseQuery(qpd, map);
                if (query.Count == 0)
                {
                    m_traceSource.TraceError("Query must provide at least one understood filter");
                    throw new InvalidOperationException(m_localizationService.GetString("error.messaging.hl7.query"));
                }
                // Control?
                var rcp = e.Message.GetStructure("RCP") as RCP;
                int? count = null, offset = 0;
                Guid queryId = Guid.NewGuid();
                if (!String.IsNullOrEmpty(rcp.QuantityLimitedRequest.Quantity.Value))
                {
                    count = Int32.Parse(rcp.QuantityLimitedRequest.Quantity.Value);
                }

                // Continuation?
                var dsc = e.Message.GetStructure("DSC") as DSC;
                if (!String.IsNullOrEmpty(dsc.ContinuationPointer.Value))
                {
                    if (!Guid.TryParse(dsc.ContinuationPointer.Value, out queryId))
                    {
                        m_traceSource.TraceError($"DSC^1 must be UUID provided by this service.");
                        throw new InvalidOperationException(m_localizationService.GetString("error.messaging.hl7.dsc"));
                    }
                }

                // Get the query tag which is the current offset
                if (ApplicationServiceContext.Current.GetService<Core.Services.IQueryPersistenceService>()?.IsRegistered(queryId) == true)
                {
                    var tag = ApplicationServiceContext.Current.GetService<Core.Services.IQueryPersistenceService>().GetQueryTag(queryId);
                    if (tag is int)
                    {
                        offset = (int)tag;
                    }
                }

                // Next, we want to get the repository for the bound type
                var repoService = ApplicationServiceContext.Current.GetService(typeof(IRepositoryService<>).MakeGenericType(map.QueryTarget));
                if (repoService == null)
                {
                    m_traceSource.TraceError($"Cannot find repository service for {map.QueryTargetXml}");
                    throw new InvalidOperationException(m_localizationService.GetString("error.messaging.hl7.repositoryService", new
                    {
                        param = map.QueryTargetXml
                    }));
                }
                // Build query
                int totalResults = 0;
                IQueryResultSet results = null;
                Expression filterQuery = null;

                if (query.TryGetValue("_id", out var _))
                {
                    Guid id = Guid.Parse(query["_id"]);
                    var result = repoService.GetType().GetMethod("Get", new Type[] { typeof(Guid) }).Invoke(repoService, new object[] { id });

                    if (result is IdentifiedData iddat)
                    {
                        results = new MemoryQueryResultSet(new List<IdentifiedData>() { iddat });
                        totalResults = 1;
                    }
                }
                else
                {
                    filterQuery = QueryExpressionParser.BuildLinqExpression(map.QueryTarget, query);

                    // Now we want to query
                    object[] parameters = { filterQuery };
                    var findMethod = repoService.GetType().GetMethod("Find", new Type[] { filterQuery.GetType() });
                    results = findMethod.Invoke(repoService, parameters) as IQueryResultSet;
                    totalResults = results.Count();

                }
                // Save the tag
                if (queryId != Guid.Empty &&
                    count.HasValue &&
                    offset.Value + count < totalResults)
                {
                    results = results.AsStateful(queryId);
                    ApplicationServiceContext.Current.GetService<Core.Services.IQueryPersistenceService>()?.SetQueryTag(queryId, count);
                }

                var resultArray = results.OfType<IdentifiedData>().ToArray();
                this.SendAuditQuery(OutcomeIndicator.Success, e.Message, resultArray);

                // Query basics
                return this.CreateQueryResponse(e, filterQuery, map, resultArray, queryId, offset.GetValueOrDefault(), count ?? 100, totalResults);
            }
            catch (Exception ex)
            {
                this.m_traceSource.TraceEvent(EventLevel.Error, "Error executing query: {0}", ex);
                this.SendAuditQuery(OutcomeIndicator.MinorFail, e.Message, null);

                // Now we construct the response
                return this.CreateNACK(map.ResponseType, e.Message, ex, e);
            }
        }

        /// <summary>
        /// Create a NACK which
        /// </summary>
        /// <param name="nackType"></param>
        /// <param name="request"></param>
        /// <param name="error"></param>
        /// <param name="receiveData"></param>
        /// <returns></returns>
        protected override IMessage CreateNACK(Type nackType, IMessage request, Exception error, Hl7MessageReceivedEventArgs receiveData)
        {
            // Get appropriate NACK type
            var msh = request.GetStructure("MSH") as MSH;
            var trigger = msh.MessageType.TriggerEvent.Value;
            var map = this.GetMapping(trigger);
            return base.CreateNACK(map.ResponseType ?? nackType, request, error, receiveData);
        }

        /// <summary>
        /// Send audit for querying
        /// </summary>
        protected virtual void SendAuditQuery(OutcomeIndicator outcome, IMessage message, IEnumerable<IdentifiedData> results)
        {
            _AuditService.Audit().ForQuery(outcome, PipeParser.Encode(message.GetStructure("QPD") as ISegment, new EncodingCharacters('|', "^~\\&")), results?.OfType<IdentifiedData>().ToArray()).Send();
        }

        /// <summary>
        /// Create an appropriate response given the results
        /// </summary>
        /// <param name="results">The results that matches the query</param>
        /// <param name="map">The HL7 query parameter mapping</param>
        /// <param name="request">The original request message</param>
        /// <param name="offset">The offset to the first result</param>
        /// <param name="count">The number of results that the user requested</param>
        /// <param name="totalResults">The total number of results present on the server.</param>
        /// <param name="queryId">The unique query identifier used</param>
        /// <param name="filter">The filter in HDSI format which was provided</param>
        /// <returns>The constructed result message</returns>
        protected virtual IMessage CreateQueryResponse(Hl7MessageReceivedEventArgs request, Expression filter, Hl7QueryParameterType map, Array results, Guid queryId, int offset, int count, int totalResults)
        {
            var retVal = this.CreateACK(map.ResponseType, request.Message, "AA", "Query Success");
            var omsh = retVal.GetStructure("MSH") as MSH;
            var qak = retVal.GetStructure("QAK") as QAK;
            var odsc = retVal.GetStructure("DSC") as DSC;
            var oqpd = retVal.GetStructure("QPD") as QPD;

            DeepCopy.Copy(request.Message.GetStructure("QPD") as ISegment, oqpd);
            omsh.MessageType.MessageCode.Value = "RSP";
            omsh.MessageType.MessageStructure.Value = retVal.GetType().Name;
            omsh.MessageType.TriggerEvent.Value = map.ResponseTrigger;
            omsh.MessageType.MessageStructure.Value = map.ResponseTypeXml;
            qak.HitCount.Value = totalResults.ToString();
            qak.HitsRemaining.Value = (totalResults - offset - count > 0 ? totalResults - offset - count : 0).ToString();
            qak.QueryResponseStatus.Value = totalResults == 0 ? "NF" : "OK";
            qak.ThisPayload.Value = results.Length.ToString();

            if (ApplicationServiceContext.Current.GetService<Core.Services.IQueryPersistenceService>() != null &&
                Int32.Parse(qak.HitsRemaining.Value) > 0)
            {
                odsc.ContinuationPointer.Value = queryId.ToString();
                odsc.ContinuationStyle.Value = "RD";
            }

            // Process results
            retVal = map.QueryHandler.AppendQueryResult(results, filter, retVal, request, offset);

            return retVal;
        }

        /// <summary>
        /// Validate that this message can be processed
        /// </summary>
        protected override bool Validate(IMessage message)
        {
            // Get the
            var msh = message.GetStructure("MSH") as MSH;
            var trigger = msh.MessageType.TriggerEvent.Value;

            if (!s_map.Map.Any(m => m.Trigger == trigger))
            {
                m_traceSource.TraceError($"{trigger} not understood or mapped");
                throw new NotSupportedException(m_localizationService.GetString("error.messaging.hl7.notUnderstood", new
                {
                    param = trigger
                }));
            }

            return true;
        }
    }
}
#pragma warning restore