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
using NHapi.Base.Parser;
using NHapi.Base.Util;
using NHapi.Model.V25.Segment;
using SanteDB.Core;
using SanteDB.Core.Model.Collection;
using SanteDB.Core.Model.Interfaces;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.Configuration;
using SanteDB.Messaging.HL7.ParameterMap;
using SanteDB.Messaging.HL7.Segments;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace SanteDB.Messaging.HL7.Utils
{
    /// <summary>
    /// Represents a query parsers utils
    /// </summary>
    public static class MessageUtils
    {
        private static readonly Dictionary<String, String> m_eventMessageMaps = new Dictionary<string, string>()
        {
            { "ADT^A40", "ADT_A39" },
            { "ADT^A01", "ADT_A01" },
            { "ADT^A04", "ADT_A01" },
            { "ADT^A05", "ADT_A01" },
            { "ADT^A08", "ADT_A01" }
        };

        // Entry ASM HASH
        private static string s_entryAsmHash;

        // Install date
        private static DateTime s_installDate;

        /// <summary>
        /// Add software information
        /// </summary>
        public static void SetDefault(this SFT sftSegment)
        {
            if (Assembly.GetEntryAssembly() == null)
            {
                return;
            }

            sftSegment.SoftwareVendorOrganization.OrganizationName.Value = Assembly.GetEntryAssembly().GetCustomAttribute<AssemblyCompanyAttribute>()?.Company;
            sftSegment.SoftwareVendorOrganization.OrganizationNameTypeCode.Value = "D";
            sftSegment.SoftwareCertifiedVersionOrReleaseNumber.Value = Assembly.GetEntryAssembly().GetName().Version.ToString();
            sftSegment.SoftwareProductName.Value = Assembly.GetEntryAssembly().GetCustomAttribute<AssemblyProductAttribute>()?.Product;

            // SFT info
            if (!String.IsNullOrEmpty(Assembly.GetEntryAssembly().Location) && File.Exists(Assembly.GetEntryAssembly().Location))
            {
                if (s_entryAsmHash == null)
                {
                    using (var md5 = MD5.Create())
                    using (var stream = File.OpenRead(Assembly.GetEntryAssembly().Location))
                    {
                        s_entryAsmHash = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "");
                    }
                }

                if (s_installDate == DateTime.MinValue)
                {
                    s_installDate = new FileInfo(Assembly.GetEntryAssembly().Location).LastWriteTime;
                }

                sftSegment.SoftwareBinaryID.Value = s_entryAsmHash;
                sftSegment.SoftwareInstallDate.Time.SetLongDate(s_installDate);
            }
        }

        /// <summary>
        /// Update the MSH header on <paramref name="msh"/> with the default information
        /// </summary>
        /// <param name="msh">The message header to be updated</param>
        /// <param name="receivingApplication">The application information that received the message</param>
        /// <param name="receivingFacility">The facility which received the message</param>
        /// <param name="security">The security value which should be sent back to the sender</param>
        public static void SetDefault(this MSH msh, String receivingApplication, String receivingFacility, String security)
        {
            var config = ApplicationServiceContext.Current.GetService<IConfigurationManager>().GetSection<Hl7ConfigurationSection>();
            msh.MessageControlID.Value = Guid.NewGuid().ToString();
            msh.SendingApplication.NamespaceID.Value = ApplicationServiceContext.Current.GetService<INetworkInformationService>()?.GetMachineName();
            msh.SendingFacility.NamespaceID.Value = config.LocalFacility.ToString();
            msh.ReceivingApplication.NamespaceID.Value = receivingApplication;
            msh.ReceivingFacility.NamespaceID.Value = receivingFacility;
            msh.Security.Value = security;
            msh.ProcessingID.ProcessingID.Value = "P";
            msh.DateTimeOfMessage.Time.Value = DateTime.Now.ToString("yyyyMMddHHmmss");
        }

        /// <summary>
        /// Parse an HL7 group (message, segment group, etc.) to a SanteDB Bundle
        /// </summary>
        /// <param name="group">The group to be parsed</param>
        /// <returns>The parsed bundle with instructions for the perssitence layer</returns>
        internal static Bundle Parse(IGroup group)
        {
            Bundle retVal = new Bundle();
            var finder = new SegmentFinder(group);
            while (finder.HasNextChild())
            {
                finder.NextChild();
                foreach (var current in finder.CurrentChildReps)
                {
                    if (current is AbstractGroupItem)
                    {
                        foreach (var s in (current as AbstractGroupItem)?.Structures.OfType<IGroup>())
                        {
                            var parsed = Parse(s);
                            retVal.Item.AddRange(parsed.Item.Select(i =>
                            {
                                var ret = i.Clone();
                                (ret as ITaggable)?.AddTag("$v2.group", current.GetStructureName());
                                return ret;
                            }));
                            retVal.FocalObjects.AddRange(parsed.FocalObjects);
                        }
                    }
                    else if (current is AbstractSegment)
                    {
                        // Empty, don't parse
                        if (PipeParser.Encode(current as AbstractSegment, new EncodingCharacters('|', "^~\\&")).Length == 3)
                        {
                            continue;
                        }

                        var handler = SegmentHandlers.GetSegmentHandler(current.GetStructureName());
                        if (handler != null)
                        {
                            var parsed = handler.Parse(current as AbstractSegment, retVal.Item);
                            if (parsed.Any())
                            {
                                retVal.FocalObjects.AddRange(parsed
                                    .OfType<ITaggable>()
                                    .Where(o => o.GetTag(Hl7Constants.FocalObjectTag) == "true")
                                    .OfType<IAnnotatedResource>()
                                    .Select(o => o.Key.GetValueOrDefault())
                                    .Where(o => Guid.Empty != o)
                                );
                                retVal.Item.AddRange(parsed.Select(i =>
                                {
                                    var ret = i.Clone();
                                    (ret as ITaggable)?.AddTag("$v2.segment", current.GetStructureName());
                                    return ret;
                                }));
                            }
                        }
                    }
                    else if (current is AbstractGroup)
                    {
                        var subObject = Parse(current as AbstractGroup);
                        retVal.Item.Add(subObject);
                        retVal.FocalObjects.AddRange(subObject.FocalObjects);
                    }

                    // Tag the objects
                }
            }

            return retVal;
        }

        /// <summary>
        /// Update the MSH on the specified MSH segment
        /// </summary>
        /// <param name="msh">The message header to be updated</param>
        /// <param name="inbound">The inbound message</param>
        public static void SetDefault(this MSH msh, MSH inbound)
        {
            var config = ApplicationServiceContext.Current.GetService<IConfigurationManager>().GetSection<Hl7ConfigurationSection>();
            msh.MessageControlID.Value = Guid.NewGuid().ToString();
            msh.SendingApplication.NamespaceID.Value = ApplicationServiceContext.Current.ApplicationName; // Assembly.GetEntryAssembly().GetName().Name; // ApplicationServiceContext.Current.GetService<INetworkInformationService>()?.GetMachineName();
            msh.SendingFacility.NamespaceID.Value = config.LocalFacility.ToString();
            msh.ReceivingApplication.NamespaceID.Value = inbound.SendingApplication.NamespaceID.Value;
            msh.ReceivingFacility.NamespaceID.Value = inbound.SendingFacility.NamespaceID.Value;
            msh.DateTimeOfMessage.Time.Value = DateTime.Now.ToString("yyyyMMddHHmmss");
        }

        /// <summary>
        /// Parse a message
        /// </summary>
        public static IMessage ParseMessage(String messageData, out string originalVersion)
        {
            Regex versionRegex = new Regex(@"^MSH\|\^\~\\\&\|(?:.*?\|){9}(.*?)[\|\r\n].*$", RegexOptions.Multiline);
            var match = versionRegex.Match(messageData);
            if (!match.Success)
            {
                throw new InvalidOperationException("Message appears to be invalid");
            }
            else
            {
                originalVersion = match.Groups[1].Value;

                // Because NHAPI is really finicky with message types we want to replace the appropriate message type
                messageData = Regex.Replace(messageData, @"^MSH\|\^\~\\\&\|(?:.*?\|){6}(.*?)[\|\r\n|\n].*$", (o) =>
                {
                    var eventRegex = Regex.Match(o.Groups[1].Value, @"^(\w{3}\^\w{3}).*$");
                    if (eventRegex.Success && m_eventMessageMaps.TryGetValue(eventRegex.Groups[1].Value, out string msgType))
                    {
                        return o.Value.Substring(0, o.Groups[1].Index) +
                            $"{eventRegex.Groups[1].Value}^{msgType}" +
                            o.Value.Substring(o.Groups[1].Index + o.Groups[1].Length);
                    }
                    return o.Value;
                }, RegexOptions.Multiline);

                PipeParser parser = new PipeParser();
                return parser.Parse(messageData, "2.5", new ParserOptions() { UnexpectedSegmentBehaviour = UnexpectedSegmentBehaviour.DropToRoot });
            }
        }

        /// <summary>
        /// Rewrite a QPD query to an HDSI query
        /// </summary>
        public static NameValueCollection ParseQueryElement(IEnumerable<Varies> varies, Hl7QueryParameterType map, String matchAlgorithm, double? matchStrength = null)
        {
            NameValueCollection retVal = new NameValueCollection();
            var config = ApplicationServiceContext.Current.GetService<IConfigurationManager>().GetSection<Hl7ConfigurationSection>();

            // Query parameters
            foreach (var qp in varies)
            {
                var composite = qp.Data as GenericComposite;

                // Parse the parameters
                var qfield = (composite.Components[0] as Varies)?.Data?.ToString();
                var qvalue = (composite.Components[1] as Varies)?.Data?.ToString();

                // Attempt to find the query parameter and map
                var parm = map.Parameters.Where(o => o.Hl7Name == qfield || o.Hl7Name == qfield + ".1" || o.Hl7Name == qfield + ".1.1").OrderBy(o => o.Hl7Name.Length - qfield.Length).FirstOrDefault();
                if (parm == null)
                {
                    throw new ArgumentOutOfRangeException($"{qfield} not mapped to query parameter");
                }

                switch (parm.ParameterType)
                {
                    case "concept":
                        retVal.Add($"{parm.ModelName}.referenceTerm.term.mnemonic", qvalue);
                        break;

                    case "string": // Enables phonetic matching
                        String transform = null;
                        if (parm.AllowFuzzy)
                        {
                            (matchAlgorithm ?? "pattern").Split(' ').ToList().ForEach(o =>
                            {
                                switch (o.ToLower())
                                {
                                    case "approx":
                                        transform = ":(approx|{0})";
                                        break;

                                    case "exact":
                                        transform = "{0}";
                                        break;

                                    case "pattern":
                                        transform = "~{0}";
                                        break;

                                    case "soundex":
                                        if (matchStrength.HasValue)
                                        {
                                            transform = ":(soundex){0}";
                                        }
                                        else
                                        {
                                            transform = $":(phonetic_diff|{{0}},soundex)<={matchStrength * qvalue.Length}";
                                        }

                                        break;

                                    case "metaphone":
                                        if (matchStrength.HasValue)
                                        {
                                            transform = ":(metaphone){0}";
                                        }
                                        else
                                        {
                                            transform = $":(phonetic_diff|{{0}},metaphone)<={matchStrength * qvalue.Length}";
                                        }

                                        break;

                                    case "dmetaphone":
                                        if (matchStrength.HasValue)
                                        {
                                            transform = ":(dmetaphone){0}";
                                        }
                                        else
                                        {
                                            transform = $":(phonetic_diff|{{0}},dmetaphone)<={matchStrength * qvalue.Length}";
                                        }

                                        break;

                                    case "alias":
                                        transform = $":(alias|{{0}})>={matchStrength ?? 0.75f}";
                                        break;

                                    default:
                                        transform = "~{0}";
                                        break;
                                }
                                retVal.Add(parm.ModelName, transform.Split(',').Select(tx => String.Format(tx, qvalue.Replace("*", "%"))));

                            });
                        }
                        else
                        {
                            transform = "~{0}";
                            retVal.Add(parm.ModelName, transform.Split(',').Select(tx => String.Format(tx, qvalue.Replace("*", "%"))));

                        }
                        break;

                    case "date":

                        if (qvalue.Length == 4) // partial date
                        {
                            retVal.Add(parm.ModelName, $"~{qvalue}");
                        }
                        else if (qvalue.Length == 6) // partial to month
                        {
                            retVal.Add(parm.ModelName, $"~{qvalue.Insert(4, "-")}");
                        }
                        else
                        {
                            retVal.Add(parm.ModelName, qvalue.Insert(4,"-").Insert(7,"-"));
                        }

                        break;

                    default:
                        var txv = parm.ValueTransform ?? "{0}";
                        retVal.Add(parm.ModelName, txv.Split(',').Select(tx => String.Format(tx, qvalue)));
                        break;
                }
            }

            // HACK: Are they asking for the @PID.3.4.1 of our local auth?
            if (retVal.TryGetValue("identifier.authority.domainName", out var localId) &&
                localId.Contains(config.LocalAuthority.DomainName))
            {
                retVal.Remove("identifier.authority.domainName");
                localId = retVal.GetValues("identifier.value");
                retVal.Remove("identifier.value");
                retVal.Add("_id", localId);
            }

            return retVal;
        }

        /// <summary>
        /// Encode the specified message
        /// </summary>
        public static String EncodeMessage(IMessage response, string originalVersion)
        {
            // Rewrite back to original version
            (response.GetStructure("MSH") as MSH).VersionID.VersionID.Value = originalVersion.Trim();
            var pp = new PipeParser();

            return pp.Encode(response);

        }
    }
}