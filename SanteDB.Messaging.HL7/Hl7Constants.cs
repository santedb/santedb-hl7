/*
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
 * User: fyfej
 * Date: 2023-6-21
 */
namespace SanteDB.Messaging.HL7
{
    /// <summary>
    /// HL7 constants
    /// </summary>
    internal static class Hl7Constants
    {
        // Trace source name
        public const string TraceSourceName = "SanteDB.Messaging.HL7";

        /// <summary>
        /// The group to which the data originally belongs or should be placed
        /// </summary>
        public const string GroupTag = "$v2.group";
        /// <summary>
        /// The segment in which the data should be placed
        /// </summary>
        public const string SegmentTag = "$v2.segment";

        // Focal object
        public const string FocalObjectTag = "$hl7.focal";

        /// <summary>
        /// Localization string like "Local identifiers must be UUIDs"
        /// </summary>
        public const string ERR_LOCAL_UUID = "error.messaging.hl7.localUuid";

        /// <summary>
        /// Localization string like "Facility {id} not found"
        /// </summary>
        public const string ERR_FACILITY_NOT_FOUND = "error.messaging.hl7.facilityId";

        /// <summary>
        /// Localization string like: "Error processing HL7 message contents"
        /// </summary>
        public const string ERR_GENERAL_PROCESSING = "error.messaging.hl7.general";

    }
}