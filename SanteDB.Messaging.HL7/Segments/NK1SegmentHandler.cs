/*
 * Copyright (C) 2021 - 2022, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
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
 * Date: 2022-5-30
 */
using NHapi.Base.Model;
using NHapi.Model.V25.Segment;
using SanteDB.Core;
using SanteDB.Core.Diagnostics;
using SanteDB.Core.Model;
using SanteDB.Core.Model.Constants;
using SanteDB.Core.Model.DataTypes;
using SanteDB.Core.Model.Entities;
using SanteDB.Core.Model.Roles;
using SanteDB.Core.Model.Security;
using SanteDB.Core.Security;
using SanteDB.Core.Security.Services;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.Configuration;
using SanteDB.Messaging.HL7.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using SanteDB.Persistence.MDM.Extensions;

namespace SanteDB.Messaging.HL7.Segments
{
    /// <summary>
    /// Represents a NK1 segment
    /// </summary>
    public class NK1SegmentHandler : ISegmentHandler, IServiceImplementation
    {
        // Next of kin relationship code system
        private const string RelationshipCodeSystem = "1.3.6.1.4.1.33349.3.1.5.9.3.200.63";

        private const string AdministrativeGenderCodeSystem = "1.3.6.1.4.1.33349.3.1.5.9.3.200.1";
        private const string ContactRoleRelationship = "1.3.6.1.4.1.33349.3.1.5.9.3.200.131";

        // Next of kin relationship types
        private Guid[] m_nextOfKinRelationshipTypes;

        // Configuration
        private Hl7ConfigurationSection m_configuration = ApplicationServiceContext.Current.GetService<IConfigurationManager>().GetSection<Hl7ConfigurationSection>();

        // Localization Service
        private readonly ILocalizationService m_localizationService = ApplicationServiceContext.Current.GetService<ILocalizationService>();

        // Tracer
        private readonly Tracer m_tracer = Tracer.GetTracer(typeof(NK1SegmentHandler));

        /// <summary>
        /// NOK relationship types
        /// </summary>
        private Guid[] NextOfKinRelationshipTypes
        {
            get
            {
                if (this.m_nextOfKinRelationshipTypes == null)
                    this.m_nextOfKinRelationshipTypes = ApplicationServiceContext.Current.GetService<IConceptRepositoryService>().GetConceptSetMembers("FamilyMember").Select(c => c.Key.Value).ToArray();
                return this.m_nextOfKinRelationshipTypes;
            }
        }

        /// <summary>
        /// NK1 segment handler ctor
        /// </summary>
        public NK1SegmentHandler()
        {
        }

        /// <summary>
        /// Gets or sets the name of the segment
        /// </summary>
        public string Name => "NK1";

        /// <summary>
        /// Get the service name
        /// </summary>
        public string ServiceName => "NK1 Segment Handler";

        /// <summary>
        /// Create next of kin relationship
        /// </summary>
        public virtual IEnumerable<ISegment> Create(IdentifiedData data, IGroup context, IdentityDomain[] exportDomains)
        {
            List<ISegment> retVal = new List<ISegment>();
            var patient = data as Patient;

            foreach (var rel in patient.LoadCollection<EntityRelationship>(nameof(Entity.Relationships)).Where(o => NextOfKinRelationshipTypes.Contains(o.RelationshipTypeKey.Value)))
            {
                var nk1 = context.GetStructure("NK1", context.GetAll("NK1").Length) as NK1;
                var person = rel.LoadProperty(o => o.TargetEntity).GetMaster() as Person;
                
                // HACK: This needs to be fixed on sync
                if (person == null) continue;

                nk1.Relationship.FromModel(rel.LoadProperty(o => o.RelationshipType), RelationshipCodeSystem, false);

                // Map person to NK1
                if (exportDomains == null || exportDomains?.Length == 0 || exportDomains?.Any(d => d.Key == this.m_configuration.LocalAuthority.Key) == true)
                {
                    nk1.GetNextOfKinAssociatedPartySIdentifiers(nk1.NextOfKinAssociatedPartySIdentifiersRepetitionsUsed).FromModel(new EntityIdentifier(this.m_configuration.LocalAuthority, person.Key.ToString()));
                    nk1.GetNextOfKinAssociatedPartySIdentifiers(nk1.NextOfKinAssociatedPartySIdentifiersRepetitionsUsed - 1).IdentifierTypeCode.Value = "PI";
                }

                // Map alternate identifiers
                foreach (var id in person.LoadCollection<EntityIdentifier>(nameof(Entity.Identifiers)))
                    if (exportDomains == null || exportDomains.Any(e => e.Key == id.IdentityDomainKey) == true)
                        nk1.GetNextOfKinAssociatedPartySIdentifiers(nk1.NextOfKinAssociatedPartySIdentifiersRepetitionsUsed).FromModel(id);

                // Addresses
                foreach (var addr in person.LoadCollection<EntityAddress>(nameof(Entity.Addresses)))
                    nk1.GetAddress(nk1.AddressRepetitionsUsed).FromModel(addr);

                // Names
                foreach (var en in person.LoadCollection<EntityName>(nameof(Entity.Names)))
                    nk1.GetName(nk1.NameRepetitionsUsed).FromModel(en);

                // Date of birth
                if (person.DateOfBirth.HasValue)
                {
                    switch (person.DateOfBirthPrecision ?? DatePrecision.Day)
                    {
                        case DatePrecision.Year:
                            nk1.DateTimeOfBirth.Time.Set(person.DateOfBirth.Value, "yyyy");
                            break;

                        case DatePrecision.Month:
                            nk1.DateTimeOfBirth.Time.Set(person.DateOfBirth.Value, "yyyyMM");
                            break;

                        case DatePrecision.Day:
                            nk1.DateTimeOfBirth.Time.Set(person.DateOfBirth.Value, "yyyyMMdd");
                            break;
                    }
                }

                // Gender
                nk1.AdministrativeSex.FromModel(person.LoadProperty(o => o.GenderConcept), AdministrativeGenderCodeSystem);

                // Telecoms
                foreach (var tel in person.LoadCollection<EntityTelecomAddress>(nameof(Entity.Telecoms)))
                {
                    if (tel.AddressUseKey.GetValueOrDefault() == AddressUseKeys.WorkPlace)
                        nk1.GetBusinessPhoneNumber(nk1.BusinessPhoneNumberRepetitionsUsed).FromModel(tel);
                    else
                        nk1.GetPhoneNumber(nk1.PhoneNumberRepetitionsUsed).FromModel(tel);
                }

                // Contact extension
                if (rel.RelationshipRoleKey.HasValue)
                {
                    nk1.ContactRole.FromModel(rel.LoadProperty(o => o.RelationshipRole), ContactRoleRelationship);
                }

                // Load relationships
                var relationships = person.LoadCollection<EntityRelationship>(nameof(Entity.Relationships));

                // Citizenships
                var citizenships = relationships.Where(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Citizen);
                foreach (var itm in citizenships)
                {
                    var ce = nk1.GetCitizenship(nk1.CitizenshipRepetitionsUsed);
                    var place = itm.LoadProperty<Place>(nameof(EntityRelationship.TargetEntity));
                    ce.Identifier.Value = place.LoadCollection<EntityIdentifier>(nameof(Entity.Identifiers)).FirstOrDefault(o => o.IdentityDomainKey == IdentityDomainKeys.Iso3166CountryCode)?.Value;
                    ce.Text.Value = place.LoadCollection<EntityName>(nameof(Entity.Names)).FirstOrDefault(o => o.NameUseKey == NameUseKeys.OfficialRecord)?.LoadCollection<EntityNameComponent>(nameof(EntityName.Component)).FirstOrDefault()?.Value;
                }

                // Language of communication
                var lang = person.LoadCollection(o => o.LanguageCommunication).FirstOrDefault(o => o.IsPreferred);
                if (lang != null)
                    nk1.PrimaryLanguage.Identifier.Value = lang.LanguageCode;

                // Protected?
                if (ApplicationServiceContext.Current.GetService<IPolicyInformationService>().GetPolicyInstance(person, DataPolicyIdentifiers.RestrictedInformation) != null)
                    nk1.ProtectionIndicator.Value = "Y";
                else
                    nk1.ProtectionIndicator.Value = "N";

                retVal.Add(nk1);
            }

            return retVal.ToArray();
        }

        /// <summary>
        /// Parse the Next Of Kin Data
        /// </summary>
        public virtual IEnumerable<IdentifiedData> Parse(ISegment segment, IEnumerable<IdentifiedData> context)
        {
            // Cast segment
            var nk1Segment = segment as NK1;
            var fieldNo = 0;
            // Person persistence service
            var personService = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Person>>();

            try
            {
                // Patient to which the parsing belongs
                var patient = context.OfType<Patient>().FirstOrDefault();
                if (patient == null)
                {
                    this.m_tracer.TraceError("NK1 Requires PID segment to be processed");

                    throw new InvalidOperationException(this.m_localizationService.GetString("error.messaging.hl7.segmentRequirement", new
                    {
                        param = "NK1",
                        param2 = "PID"
                    }));
                }

                // Next of kin is a person
                Person retVal = new Person() { Key = Guid.NewGuid(), Relationships = new List<EntityRelationship>() };
                EntityRelationship retValRelation = new EntityRelationship(EntityRelationshipTypeKeys.NextOfKin, retVal.Key) { SourceEntityKey = patient.Key };
                bool foundByKey = false;

                // Look for existing person
                fieldNo = 33;
                foreach (var id in nk1Segment.GetNextOfKinAssociatedPartySIdentifiers())
                {
                    var idnumber = id.IDNumber.Value;
                    IdentityDomain authority = null;
                    try
                    {
                        authority = id.AssigningAuthority.ToModel();
                    }
                    catch (Exception e)
                    {
                        throw new HL7ProcessingException(e.Message, "NK1", nk1Segment.SetIDNK1.Value, 33, 3, e);
                    }
                    Guid idguid = Guid.Empty;
                    int tr = 0;
                    Person found = null;
                    if (authority.Key == this.m_configuration.LocalAuthority.Key || 
                        authority.DomainName == this.m_configuration.LocalAuthority.DomainName)
                    {
                        found = personService.Get(Guid.Parse(id.IDNumber.Value), null, AuthenticationContext.SystemPrincipal);
                    }
                    else if (authority?.IsUnique == true)
                        found = personService.Query(o => o.Identifiers.Any(i => i.Value == idnumber && i.IdentityDomain.Key == authority.Key), AuthenticationContext.SystemPrincipal).AsResultSet().Take(1).FirstOrDefault();
                    if (found != null)
                    {
                        retVal = found;
                        foundByKey = true;
                        // Existing relationship?
                        retValRelation = ApplicationServiceContext.Current.GetService<IDataPersistenceService<EntityRelationship>>().Query(r => r.SourceEntityKey == patient.Key.Value && r.TargetEntityKey == retVal.Key.Value, AuthenticationContext.SystemPrincipal).FirstOrDefault() ?? retValRelation;
                        break;
                    }
                }

               
                // Relationship type
                fieldNo = 3;
                if (!nk1Segment.Relationship.IsEmpty())
                    retValRelation.RelationshipTypeKey = nk1Segment.Relationship.ToModel(RelationshipCodeSystem)?.Key;

                // Some relationships only allow one person, we should update them
                var existingNokRel = patient.LoadProperty(o=>o.Relationships).FirstOrDefault(o => o.RelationshipTypeKey == retValRelation.RelationshipTypeKey);
                if (existingNokRel != null)
                {
                    retValRelation = existingNokRel;
                    if (!foundByKey) // We didn't actually resolve anyone by current key so we should try to find them in the DB
                    {
                        retVal = context.FirstOrDefault(o => o.Key == existingNokRel.TargetEntityKey) as Person;
                        // Mother isn't in context, load
                        if (retVal == null)
                        {
                            retVal = personService.Get(existingNokRel.TargetEntityKey.Value, null, AuthenticationContext.SystemPrincipal);
                        }
                        if (retVal == null)
                        {
                            throw new InvalidOperationException(this.m_localizationService.GetString("error.messaging.hl7.entityNOK"));
                        }

                        // IF the person is a PATIENT and not a PERSON we will not update them - too dangerous - ignore the NOK entry
                        if (retVal is Patient && !foundByKey)
                            return new IdentifiedData[0];
                    }
                }

                fieldNo = 2;
                // Names
                if (nk1Segment.NameRepetitionsUsed > 0)
                    foreach (var itm in nk1Segment.GetName())
                    {
                        var model = itm.ToModel();
                        var existing = retVal.LoadProperty(o=>o.Names).FirstOrDefault(o => o.NameUseKey == model.NameUseKey);
                        if (existing == null)
                            retVal.Names.Add(model);
                        else
                            existing.CopyObjectData(model);
                    }

                // Address
                fieldNo = 4;
                if (nk1Segment.AddressRepetitionsUsed > 0)
                    foreach (var itm in nk1Segment.GetAddress())
                    {
                        var model = itm.ToModel();
                        var existing = retVal.LoadProperty(o=>o.Addresses).FirstOrDefault(o => o.AddressUseKey == model.AddressUseKey);
                        if (existing == null)
                            retVal.Addresses.Add(model);
                        else
                            existing.CopyObjectData(model);
                    }

                // Phone numbers
                fieldNo = 5;
                var telecoms = nk1Segment.GetBusinessPhoneNumber().Union(nk1Segment.GetPhoneNumber());
                foreach (var itm in telecoms)
                {
                    var model = itm.ToModel();
                    var existing = retVal.LoadProperty(o=>o.Telecoms).FirstOrDefault(o => o.AddressUseKey == model.AddressUseKey);
                    if (existing == null)
                        retVal.Telecoms.Add(model);
                    else
                        existing.CopyObjectData(model);
                }

                fieldNo = 15;
                if (!nk1Segment.AdministrativeSex.IsEmpty())
                    retVal.GenderConcept = nk1Segment.AdministrativeSex.ToConcept(AdministrativeGenderCodeSystem);

                // Organization
                fieldNo = 13;
                if (nk1Segment.OrganizationNameNK1RepetitionsUsed > 0)
                {
                    var orgService = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Organization>>();
                    foreach (var xon in nk1Segment.GetOrganizationNameNK1())
                    {
                        var id = xon.ToModel();
                        // Lookup the organization scoper
                        if (id != null)
                        {
                            var organization = orgService?.Query(o => o.Identifiers.Any(i => i.Value == id.Value && i.IdentityDomainKey == id.IdentityDomainKey), AuthenticationContext.SystemPrincipal).FirstOrDefault();
                            if (organization == null && !this.m_configuration.StrictMetadataMatch)
                            {
                                organization = new Organization()
                                {
                                    Identifiers = new List<EntityIdentifier>() { id },
                                    Names = new List<EntityName>() { new EntityName(NameUseKeys.Assigned, xon.OrganizationName.Value) }
                                };
                                retVal.LoadProperty(o=>o.Relationships).Add(new EntityRelationship(EntityRelationshipTypeKeys.Scoper, organization)
                                {
                                    ClassificationKey = RelationshipClassKeys.ContainedObjectLink
                                });
                            }
                            else
                            {
                                retVal.LoadProperty(o => o.Relationships).Add(new EntityRelationship(EntityRelationshipTypeKeys.Scoper, organization));
                            }
                        }
                        else
                        {
                            this.m_tracer.TraceError("XON requires identifier");
                            throw new HL7DatatypeProcessingException(this.m_localizationService.GetString("error.messaging.hl7.requirementXON"), 10, new ArgumentNullException());
                        }
                    }
                }
                // Context role, when the person should be contact
                fieldNo = 7;
                if (!nk1Segment.ContactRole.IsEmpty())
                {
                    var existingConRole = patient.Relationships.FirstOrDefault(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Contact && retVal.Key == o.TargetEntityKey);
                    if (existingConRole == null)
                    {
                        patient.LoadProperty(o => o.Relationships).Add(new EntityRelationship(EntityRelationshipTypeKeys.Contact, retVal.Key)
                        {
                            RelationshipRole = nk1Segment.ContactRole.ToModel(ContactRoleRelationship, true)
                        });
                    }
                    else
                        existingConRole.RelationshipRole = nk1Segment.ContactRole.ToModel(ContactRoleRelationship, true);
                }

                fieldNo = 16;
                if (!nk1Segment.DateTimeOfBirth.IsEmpty())
                {
                    retVal.DateOfBirth = nk1Segment.DateTimeOfBirth.ToModel();
                    retVal.DateOfBirthPrecision = nk1Segment.DateTimeOfBirth.ToDatePrecision();
                }

                // Citizenship
                fieldNo = 19;
                if (nk1Segment.CitizenshipRepetitionsUsed > 0)
                {
                    foreach (var cit in nk1Segment.GetCitizenship())
                    {
                        var place = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Place>>()?.Query(o => o.Identifiers.Any(i => i.Value == cit.Identifier.Value && i.IdentityDomain.Key == IdentityDomainKeys.Iso3166CountryCode), AuthenticationContext.SystemPrincipal).FirstOrDefault();
                        if (place != null)
                        {
                            if (!retVal.LoadProperty(o => o.Relationships).Any(r => r.RelationshipTypeKey == EntityRelationshipTypeKeys.Citizen && r.TargetEntityKey == place.Key))
                            {
                                retVal.Relationships.Add(new EntityRelationship(EntityRelationshipTypeKeys.Citizen, place.Key));
                            }
                        }
                        else
                        {
                            this.m_tracer.TraceError($"Cannot find country with code {cit.Identifier.Value}");
                            throw new KeyNotFoundException(this.m_localizationService.GetString("error.messaging.hl7.countryCode", new
                            {
                                param = cit.Identifier.Value
                            }));
                        }
                    }
                }

                fieldNo = 20;
                if (!nk1Segment.PrimaryLanguage.IsEmpty())
                    retVal.LanguageCommunication = new List<PersonLanguageCommunication>()
                    {
                        new PersonLanguageCommunication(nk1Segment.PrimaryLanguage.Identifier.Value.ToLower(), true)
                    };

                // Privacy code
                fieldNo = 23;
                if (!nk1Segment.ProtectionIndicator.IsEmpty())
                {
                    var pip = ApplicationServiceContext.Current.GetService<IDataPersistenceService<SecurityPolicy>>();
                    if (nk1Segment.ProtectionIndicator.Value == "Y")
                        retVal.AddPolicy(DataPolicyIdentifiers.RestrictedInformation);
                    else if (nk1Segment.ProtectionIndicator.Value == "N")
                        retVal.Policies.Clear();
                    else
                    {
                        this.m_tracer.TraceError($"Protection indicator {nk1Segment.ProtectionIndicator.Value} is invalid");
                        throw new ArgumentOutOfRangeException(this.m_localizationService.GetString("error.messaging.hl7.protectionInvalid",
                            new
                            {
                                param = nk1Segment.ProtectionIndicator.Value
                            }));
                    }
                }

                // Associated person identifiers
                fieldNo = 33;
                if (nk1Segment.NextOfKinAssociatedPartySIdentifiersRepetitionsUsed > 0)
                {
                    retVal.Identifiers.AddRange(nk1Segment.GetNextOfKinAssociatedPartySIdentifiers().ToModel().ToList().Where(i => !retVal.Identifiers.Any(e => e.SemanticEquals(i))));
                }

                // Find the existing relationship on the patient
                if (!patient.LoadProperty(o => o.Relationships).Any(o => o.RelationshipTypeKey == retValRelation.RelationshipTypeKey && o.TargetEntityKey == retValRelation.TargetEntityKey))
                {
                    patient.Relationships.Add(retValRelation);
                }

                if (!context.Contains(retVal))
                    return new IdentifiedData[] { retVal };
                else
                    return new IdentifiedData[0];
            }
            catch (HL7ProcessingException) // Just re-throw
            {
                throw;
            }
            catch (HL7DatatypeProcessingException e)
            {
                throw new HL7ProcessingException(this.m_localizationService.GetString(Hl7Constants.ERR_GENERAL_PROCESSING), "NK1", nk1Segment.SetIDNK1.Value, fieldNo, e.Component, e);
            }
            catch (Exception e)
            {
                throw new HL7ProcessingException(this.m_localizationService.GetString(Hl7Constants.ERR_GENERAL_PROCESSING), "NK1", nk1Segment.SetIDNK1.Value, fieldNo, 1, e);
            }
        }
    }
}