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
using SanteDB.Core;
using SanteDB.Core.Services;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SanteDB.Messaging.HL7.Segments
{
    /// <summary>
    /// Represents a segment handler.
    /// </summary>
    public static class SegmentHandlers
    {
        // Segment handlers
        private static readonly Dictionary<string, ISegmentHandler> s_segmentHandlers = new Dictionary<string, ISegmentHandler>();

        /// <summary>
        /// Scan types for message handler
        /// </summary>
        static SegmentHandlers()
        {
            foreach (var t in AppDomain.CurrentDomain.GetAllTypes().Where(t => typeof(ISegmentHandler).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface))
            {
                var instance = ApplicationServiceContext.Current.GetService<IServiceManager>().CreateInjected(t) as ISegmentHandler;
                s_segmentHandlers.Add(instance.Name, instance);
            }
        }

        /// <summary>
        /// Gets the segment handler for the specified segment
        /// </summary>
        public static ISegmentHandler GetSegmentHandler(string name)
        {
            s_segmentHandlers.TryGetValue(name, out var handler);
            return handler;
        }
    }
}