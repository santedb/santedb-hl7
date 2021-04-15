using NHapi.Base.Model;
using SanteDB.Core;
using SanteDB.Core.Model;
using SanteDB.Core.Model.DataTypes;
using SanteDB.Core.Model.Roles;
using SanteDB.Core.Services;
using System;
using System.Collections.Generic;
using System.Text;
using NHapi.Model.V25.Segment;
using SanteDB.Messaging.HL7.Exceptions;
using SanteDB.Messaging.HL7.Configuration;
using System.Linq;
using SanteDB.Core.Model.Constants;

namespace SanteDB.Messaging.HL7.Segments
{
    /// <summary>
    /// Segment handler that handles the MRG segment
    /// </summary>
    public class MRGSegmentHandler : ISegmentHandler
    {

        private Hl7ConfigurationSection m_configuration = ApplicationServiceContext.Current.GetService<IConfigurationManager>().GetSection<Hl7ConfigurationSection>();

        /// <summary>
        /// Get the name of the segment
        /// </summary>
        public string Name => "MRG";

        /// <summary>
        /// Create the MRG segment
        /// </summary>
        public IEnumerable<ISegment> Create(IdentifiedData data, IGroup context, AssigningAuthority[] exportDomains)
        {
            // TODO: When broadcasting a MRG event this will need to be constructed only
            throw new NotImplementedException();
        }

        /// <summary>
        /// Parse the segment handler
        /// </summary>
        public IEnumerable<IdentifiedData> Parse(ISegment segment, IEnumerable<IdentifiedData> context)
        {
            var mrgSegment = segment as MRG;

            try
            {
                var patient = context.OfType<Patient>().FirstOrDefault();
                if (patient == null)
                    throw new InvalidOperationException("MRG Requires PID segment to be processed");

                var patientService = ApplicationServiceContext.Current.GetService<IRepositoryService<Patient>>();

                Patient found = null;

                // Parse the MRG-1 Segment
                foreach (var id in mrgSegment.GetPriorPatientIdentifierList())
                {
                    var idnumber = id.IDNumber.Value;
                    AssigningAuthority authority;
                    try
                    {
                        authority = id.AssigningAuthority.ToModel();
                    }
                    catch (Exception e)
                    {
                        throw new HL7ProcessingException("Error processig assigning authority", "MRG", "1", 1, 4, e);
                    }

                    if (authority == null)
                        throw new HL7ProcessingException($"No authority configured for {id.AssigningAuthority.NamespaceID.Value}", "PID", pidSegment.SetIDPID.Value, 3, 4);
                    
                    // Find by local authority or by UUID
                    Guid idguid = Guid.Empty;
                    if (authority.Key == this.m_configuration.LocalAuthority.Key)
                    {
                        found = patientService.Get(Guid.Parse(id.IDNumber.Value), Guid.Empty);
                    }
                    else if (authority?.IsUnique == true)
                    {
                        found = patientService.Find(o => o.Identifiers.Any(i => i.Authority.Key == authority.Key && i.Value == idnumber)).FirstOrDefault();
                    }

                    // Found
                    if(found != null) { break; }
                }

                if(found == null)
                {
                    throw new KeyNotFoundException($"MRG Patient Not Found");
                }

                // The old is obsolete
                found.StatusConceptKey = StatusKeys.Obsolete;
                // PID replaces MRG
                patient.Relationships.Add(new Core.Model.Entities.EntityRelationship(EntityRelationshipTypeKeys.Replaces, found.Key));
                return new IdentifiedData[] { found };
            }
            catch (HL7ProcessingException e) // Just re-throw
            {
                throw;
            }
            catch (HL7DatatypeProcessingException e)
            {
                throw new HL7ProcessingException("Error processing MRG segment", "PID", "1", 1, e.Component, e);
            }
            catch (Exception e)
            {
                throw new HL7ProcessingException("Error processing MRG segment", "PID", "1", 1, 1, e);
            }
        }
    }
}
