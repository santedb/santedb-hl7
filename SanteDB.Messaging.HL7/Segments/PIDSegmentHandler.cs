﻿/*
 * Portions Copyright 2019-2020, Fyfe Software Inc. and the SanteSuite Contributors (See NOTICE)
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
 * User: fyfej (Justin Fyfe)
 * Date: 2019-11-27
 */
using SanteDB.Core.Model;
using SanteDB.Core.Model.Acts;
using SanteDB.Core.Model.Constants;
using SanteDB.Core.Model.DataTypes;
using SanteDB.Core.Model.Entities;
using SanteDB.Core.Model.Roles;
using SanteDB.Core.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using NHapi.Model.V25.Datatype;
using NHapi.Base.Model;
using NHapi.Model.V25.Segment;
using SanteDB.Core;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.Configuration;
using SanteDB.Messaging.HL7.Exceptions;

namespace SanteDB.Messaging.HL7.Segments
{
    /// <summary>
    /// Represents a segment handler which handles PID segments
    /// </summary>
    public class PIDSegmentHandler : ISegmentHandler
    {

        private const string AdministrativeGenderCodeSystem = "1.3.6.1.4.1.33349.3.1.5.9.3.200.1";
        private const string RaceCodeSystem = "2.16.840.1.113883.5.5";
        private const string MaritalStatusCodeSystem = "1.3.6.1.4.1.33349.3.1.5.9.3.200.2";
        private const string ReligionCodeSystem = "1.3.6.1.4.1.33349.3.1.5.9.3.200.6";
        private const string EthnicGroupCodeSystem = "1.3.6.1.4.1.33349.3.1.5.9.3.200.189";

        private readonly Guid[] AddressHierarchy = {
            EntityClassKeys.ServiceDeliveryLocation,
            EntityClassKeys.CityOrTown,
            EntityClassKeys.CountyOrParish,
            EntityClassKeys.State,
            EntityClassKeys.Country,
            EntityClassKeys.Place
        };

        private Hl7ConfigurationSection m_configuration = ApplicationServiceContext.Current.GetService<IConfigurationManager>().GetSection<Hl7ConfigurationSection>();

        /// <summary>
        /// Gets the name of the segment
        /// </summary>
        public string Name => "PID";

        /// <summary>
        /// Create the PID segment from data elements
        /// </summary>
        /// <param name="data">The data to be created</param>
        /// <param name="context">The message in which the segment is created</param>
        /// <returns>The segments to add to the messge</returns>
        public virtual IEnumerable<ISegment> Create(IdentifiedData data, IGroup context, AssigningAuthority[] exportDomains)
        {
            var retVal = context.GetStructure("PID") as PID;
            var patient = data as Patient;
            if (patient == null)
                throw new InvalidOperationException($"Cannot convert {data.GetType().Name} to PID");

            // Map patient to PID
            if (exportDomains == null || exportDomains?.Length == 0 || exportDomains?.Any(d => d.Key == this.m_configuration.LocalAuthority.Key) == true)
            {
                retVal.GetPatientIdentifierList(retVal.PatientIdentifierListRepetitionsUsed).FromModel(new EntityIdentifier(this.m_configuration.LocalAuthority, patient.Key.ToString()));
                retVal.GetPatientIdentifierList(retVal.PatientIdentifierListRepetitionsUsed - 1).IdentifierTypeCode.Value = "PI";
            }

            // Map alternate identifiers
            foreach (var id in patient.GetIdentifiers())
            {
                if (exportDomains == null || exportDomains.Any(e => e.Key == id.AuthorityKey) == true)
                {
                    retVal.GetPatientIdentifierList(retVal.PatientIdentifierListRepetitionsUsed).FromModel(id);
                    if (id.Authority.DomainName == this.m_configuration.SsnAuthority?.DomainName ||
                        id.Authority.Oid == this.m_configuration.SsnAuthority?.Oid)
                        retVal.SSNNumberPatient.Value = id.Value;
                }
            }

            // Addresses
            foreach (var addr in patient.GetAddresses())
                retVal.GetPatientAddress(retVal.PatientAddressRepetitionsUsed).FromModel(addr);

            // Names
            foreach (var en in patient.GetNames())
                retVal.GetPatientName(retVal.PatientNameRepetitionsUsed).FromModel(en);

            // Date of birth
            if (patient.DateOfBirth.HasValue)
            {
                switch (patient.DateOfBirthPrecision ?? DatePrecision.Day)
                {
                    case DatePrecision.Year:
                        retVal.DateTimeOfBirth.Time.Set(patient.DateOfBirth.Value, "yyyy");
                        break;
                    case DatePrecision.Month:
                        retVal.DateTimeOfBirth.Time.Set(patient.DateOfBirth.Value, "yyyyMM");
                        break;
                    case DatePrecision.Day:
                        retVal.DateTimeOfBirth.Time.Set(patient.DateOfBirth.Value, "yyyyMMdd");
                        break;
                }
            }

            // Gender
            retVal.AdministrativeSex.FromModel(patient.LoadProperty<Concept>("GenderConcept"), AdministrativeGenderCodeSystem);

            // Deceased date
            if (patient.DeceasedDate.HasValue)
            {
                if (patient.DeceasedDate == DateTime.MinValue)
                    retVal.PatientDeathIndicator.Value = "Y";
                else
                    switch (patient.DeceasedDatePrecision ?? DatePrecision.Day)
                    {
                        case DatePrecision.Year:
                            retVal.PatientDeathDateAndTime.Time.Set(patient.DeceasedDate.Value, "yyyy");
                            break;
                        case DatePrecision.Month:
                            retVal.PatientDeathDateAndTime.Time.Set(patient.DeceasedDate.Value, "yyyyMM");
                            break;
                        case DatePrecision.Day:
                            retVal.PatientDeathDateAndTime.Time.Set(patient.DeceasedDate.Value, "yyyyMMdd");
                            break;
                    }
            }

            // Mother's info
            var motherRelation = patient.GetRelationships().FirstOrDefault(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Mother);
            if (motherRelation != null)
            {
                var mother = motherRelation.LoadProperty(nameof(EntityRelationship.TargetEntity)) as Person;
                foreach (var nam in mother.GetNames().Where(n => n.NameUseKey == NameUseKeys.MaidenName))
                    retVal.GetMotherSMaidenName(retVal.MotherSMaidenNameRepetitionsUsed).FromModel(nam);
                foreach (var id in mother.GetIdentifiers())
                    retVal.GetMotherSIdentifier(retVal.MotherSIdentifierRepetitionsUsed).FromModel(id);
            }

            // Telecoms
            foreach (var tel in patient.GetTelecoms())
            {
                if (tel.AddressUseKey.GetValueOrDefault() == AddressUseKeys.WorkPlace)
                    retVal.GetPhoneNumberBusiness(retVal.PhoneNumberBusinessRepetitionsUsed).FromModel(tel);
                else
                    retVal.GetPhoneNumberHome(retVal.PhoneNumberHomeRepetitionsUsed).FromModel(tel);
            }

            // Load relationships
            var relationships = patient.GetRelationships();
            var participations = patient.LoadCollection<ActParticipation>(nameof(Entity.Participations));

            // Birthplace
            var birthplace = relationships.FirstOrDefault(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Birthplace);
            if (birthplace != null)
                retVal.BirthPlace.Value = birthplace.LoadProperty<Entity>(nameof(EntityRelationship.TargetEntity)).GetNames().FirstOrDefault()?.LoadCollection<EntityNameComponent>(nameof(EntityName.Component)).FirstOrDefault()?.Value;

            // Citizenships
            var citizenships = relationships.Where(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Citizen);
            foreach (var itm in citizenships)
            {
                var ce = retVal.GetCitizenship(retVal.CitizenshipRepetitionsUsed);
                var place = itm.LoadProperty<Place>(nameof(EntityRelationship.TargetEntity));
                ce.Identifier.Value = place.GetIdentifiers().FirstOrDefault(o => o.AuthorityKey == AssigningAuthorityKeys.Iso3166CountryCode)?.Value;
                ce.Text.Value = place.GetNames().FirstOrDefault(o => o.NameUseKey == NameUseKeys.OfficialRecord)?.LoadCollection<EntityNameComponent>(nameof(EntityName.Component)).FirstOrDefault()?.Value;
            }

            // Account number
            var account = participations.FirstOrDefault(o => o.ParticipationRoleKey == ActParticipationKey.Holder && o.LoadProperty<Account>(nameof(ActParticipation.Act)) != null);
            if (account != null)
                retVal.PatientAccountNumber.FromModel(account.Act.Identifiers.FirstOrDefault() ?? new ActIdentifier(this.m_configuration.LocalAuthority, account.Key.ToString()));

            // Marital status
            if (patient.MaritalStatusKey.HasValue)
                retVal.MaritalStatus.FromModel(patient.LoadProperty<Concept>(nameof(Patient.MaritalStatus)), MaritalStatusCodeSystem);

            // Religion
            if (patient.ReligiousAffiliationKey.HasValue)
                retVal.Religion.FromModel(patient.LoadProperty<Concept>(nameof(Patient.ReligiousAffiliation)), ReligionCodeSystem);

            // Ethnic groups
            if (patient.EthnicGroupCodeKey.HasValue)
                retVal.GetEthnicGroup(0).FromModel(patient.LoadProperty<Concept>(nameof(Patient.EthnicGroup)), EthnicGroupCodeSystem);

            // Primary language
            var lang = patient.LoadCollection<PersonLanguageCommunication>(nameof(Patient.LanguageCommunication)).FirstOrDefault(o => o.IsPreferred);
            if (lang != null)
                retVal.PrimaryLanguage.Identifier.Value = lang.LanguageCode;

            return new ISegment[] { retVal };
        }

        /// <summary>
        /// Parse the parse the specified segment into a patient object
        /// </summary>
        /// <param name="segment">The segment to be parsed</param>
        /// <returns>The parsed patient information</returns>
        public virtual IEnumerable<IdentifiedData> Parse(ISegment segment, IEnumerable<IdentifiedData> context)
        {
            var patientService = ApplicationServiceContext.Current.GetService<IRepositoryService<Patient>>();
            var personService = ApplicationServiceContext.Current.GetService<IRepositoryService<Person>>();
            var pidSegment = segment as PID;
            int fieldNo = 0;

            try
            {

                Patient retVal = new Patient() { Key = Guid.NewGuid(), StatusConceptKey = StatusKeys.Active };
                Person motherEntity = null;
                List<IdentifiedData> retCollection = new List<IdentifiedData>();

                retVal.CreationAct = context.OfType<ControlAct>().FirstOrDefault();

                // Existing patient?
                if (pidSegment.Message.GetStructureName().StartsWith("ADT"))
                {
                    foreach (var id in pidSegment.GetPatientIdentifierList())
                    {
                        var idnumber = id.IDNumber.Value;
                        AssigningAuthority authority;
                        try
                        {
                            authority = id.AssigningAuthority.ToModel();
                        }
                        catch (Exception e)
                        {
                            throw new HL7ProcessingException("Error processig assigning authority", "PID", pidSegment.SetIDPID.Value, 3, 4, e);
                        }

                        if (authority == null)
                            throw new HL7ProcessingException($"No authority configured for {id.AssigningAuthority.NamespaceID.Value}", "PID", pidSegment.SetIDPID.Value, 3, 4);
                        Guid idguid = Guid.Empty;
                        Person found = null;
                        if (authority.Key == this.m_configuration.LocalAuthority.Key)
                        {
                            found = patientService.Get(Guid.Parse(id.IDNumber.Value), Guid.Empty);
                            if (found == null)
                                found = personService.Get(Guid.Parse(id.IDNumber.Value), Guid.Empty);
                        }
                        else if (authority?.IsUnique == true)
                        {
                            found = patientService.Find(o => o.Identifiers.Any(i => i.Authority.Key == authority.Key && i.Value == idnumber)).FirstOrDefault();
                            if (found == null)
                                found = personService.Find(o => o.Identifiers.Any(i => i.Authority.Key == authority.Key && i.Value == idnumber)).FirstOrDefault();

                        }

                        if (found != null)
                        {
                            if (found is Patient)
                                retVal = (Patient)found.Clone();
                            else // We need to upgrade this person
                            {
                                retVal.CopyObjectData(found, false, true);
                                retVal.Tags.Add(new EntityTag("$sys.reclass", "true"));
                            }
                            break;
                        }
                    }
                }


                fieldNo = 2;
                if (!pidSegment.PatientID.IsEmpty())
                    retVal.Identifiers.Add(pidSegment.PatientID.ToModel());


                fieldNo = 3;
                if (pidSegment.PatientIdentifierListRepetitionsUsed > 0)
                {
                    var messageIdentifiers = pidSegment.GetPatientIdentifierList().ToModel();

                    if (this.m_configuration.IdentifierReplacementBehavior == IdentifierReplacementMode.AnyInDomain)
                        retVal.Identifiers.RemoveAll(o => messageIdentifiers.Any(i => i.EffectiveVersionSequenceId.HasValue && i.AuthorityKey == o.AuthorityKey));

                    // Remove any identifiers matching the value explicitly 
                    retVal.Identifiers.RemoveAll(o => messageIdentifiers.Any(i => i.ObsoleteVersionSequenceId.HasValue && i.AuthorityKey == o.AuthorityKey && i.Value == o.Value));

                    // Add any identifiers which we don't have any other identifier domain for
                    retVal.Identifiers.AddRange(messageIdentifiers.Where(o => !o.ObsoleteVersionSequenceId.HasValue && !retVal.Identifiers.Any(i => i.Authority.Key == o.AuthorityKey && i.Value == o.Value)));
                }

                // Find the key for the patient 
                var keyId = pidSegment.GetPatientIdentifierList().FirstOrDefault(o => o.AssigningAuthority.NamespaceID.Value == this.m_configuration.LocalAuthority.DomainName);
                if (keyId != null)
                    retVal.Key = Guid.Parse(keyId.IDNumber.Value);

                if (retVal.Identifiers.Count == 0)
                    throw new HL7ProcessingException("Couldn't understand any patient identity", "PID", pidSegment.SetIDPID.Value, 3, 1);

                fieldNo = 5;
                if (pidSegment.PatientNameRepetitionsUsed > 0)
                    foreach (var itm in pidSegment.GetPatientName())
                    {
                        var model = itm.ToModel();
                        var existing = retVal.Names.FirstOrDefault(o => o.NameUseKey == model.NameUseKey);
                        if (existing == null)
                            retVal.Names.Add(model);
                        else
                            existing.CopyObjectData(model);
                    }

                fieldNo = 21;
                // Mother's maiden name, create a relationship for mother
                if (pidSegment.MotherSMaidenNameRepetitionsUsed > 0 || pidSegment.MotherSIdentifierRepetitionsUsed > 0)
                {
                    // Attempt to find the mother
                    foreach (var id in pidSegment.GetMotherSIdentifier())
                    {
                        AssigningAuthority authority = null;
                        try
                        {
                            authority = id.AssigningAuthority.ToModel();
                        }
                        catch (Exception e)
                        {
                            throw new HL7ProcessingException("Error processing mother's identifiers", "PID", pidSegment.SetIDPID.Value, 21, 3);
                        }

                        if (authority.Key == this.m_configuration.LocalAuthority.Key)
                            motherEntity = personService.Get(Guid.Parse(id.IDNumber.Value), Guid.Empty);
                        else if (authority?.IsUnique == true)
                            motherEntity = personService.Find(o => o.Identifiers.Any(i => i.Value == id.IDNumber.Value && i.Authority.Key == authority.Key)).FirstOrDefault();
                    }

                    fieldNo = 6;
                    // Mother doesn't exist, so add it
                    var foundById = motherEntity != null;
                    if (!foundById)
                        motherEntity = new Person()
                        {
                            Key = Guid.NewGuid(),
                            Identifiers = pidSegment.GetMotherSIdentifier().ToModel().ToList(),
                            Names = pidSegment.GetMotherSMaidenName().ToModel(NameUseKeys.MaidenName).ToList(),
                            StatusConceptKey = StatusKeys.Active

                        };

                    var existingRelationship = retVal.Relationships.FirstOrDefault(r => r.SourceEntityKey == retVal.Key && r.TargetEntityKey == motherEntity.Key);
                    if (existingRelationship == null)
                    {
                        // Find by mother relationship
                        existingRelationship = retVal.Relationships.FirstOrDefault(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Mother);
                        if (existingRelationship == null) // No current mother relationship
                            retVal.Relationships.Add(new EntityRelationship(EntityRelationshipTypeKeys.Mother, motherEntity.Key));
                        else
                        {
                            var mother = existingRelationship.LoadProperty<Entity>("TargetEntity");

                            // Was the data found by ID? If so point at it
                            if (foundById)
                                existingRelationship.TargetEntityKey = motherEntity.Key;
                            else
                            {
                                // was not found by ID so only update the name of existing mother entity - Check for validity
                                var newMaidenName = pidSegment.GetMotherSMaidenName().ToModel(NameUseKeys.MaidenName).FirstOrDefault();
                                if (!mother.GetNames().Any(e => e.SemanticEquals(newMaidenName)))
                                {
                                    mother.Names.Add((newMaidenName)); // Add it
                                    motherEntity = mother as Person;
                                }
                            }
                        }
                    }
                    else
                        existingRelationship.RelationshipTypeKey = EntityRelationshipTypeKeys.Mother;

                }

                // Date/time of birth
                fieldNo = 7;
                if (!pidSegment.DateTimeOfBirth.IsEmpty())
                {
                    retVal.DateOfBirth = pidSegment.DateTimeOfBirth.ToModel();
                    retVal.DateOfBirthPrecision = pidSegment.DateTimeOfBirth.ToDatePrecision();
                }

                // Administrative gender
                fieldNo = 8;
                if (!pidSegment.AdministrativeSex.IsEmpty())
                    retVal.GenderConcept = pidSegment.AdministrativeSex.ToConcept(AdministrativeGenderCodeSystem);

                // Patient Alias
                fieldNo = 9;
                if (pidSegment.PatientAliasRepetitionsUsed > 0)
                    retVal.Names.AddRange(pidSegment.GetPatientAlias().ToModel());

                // Race codes
                fieldNo = 10;
                if (pidSegment.RaceRepetitionsUsed > 0)
                    ; // TODO: Implement as an extension if needed 

                // Addresses
                fieldNo = 11;
                if (pidSegment.PatientAddressRepetitionsUsed > 0)
                    foreach (var itm in pidSegment.GetPatientAddress())
                    {
                        var model = itm.ToModel();
                        var existing = retVal.Addresses.FirstOrDefault(o => o.AddressUseKey == model.AddressUseKey);
                        if (existing == null)
                            retVal.Addresses.Add(model);
                        else
                            existing.CopyObjectData(model);
                    }

                // Fields
                fieldNo = 13;
                var telecoms = pidSegment.GetPhoneNumberBusiness().Union(pidSegment.GetPhoneNumberHome());
                foreach (var itm in telecoms)
                {
                    var model = itm.ToModel();
                    var existing = retVal.Telecoms.FirstOrDefault(o => o.AddressUseKey == model.AddressUseKey);
                    if (existing == null)
                        retVal.Telecoms.Add(model);
                    else
                        existing.CopyObjectData(model);
                }

                // Language
                if (!pidSegment.PrimaryLanguage.IsEmpty())
                    retVal.LanguageCommunication = new List<PersonLanguageCommunication>()
                {
                    new PersonLanguageCommunication(pidSegment.PrimaryLanguage.Identifier.Value.ToLower(), true)
                };

                // Marital Status
                fieldNo = 16;
                if (!pidSegment.MaritalStatus.IsEmpty())
                    retVal.MaritalStatus = pidSegment.MaritalStatus.ToModel(MaritalStatusCodeSystem);

                // Religion
                fieldNo = 17;
                if (!pidSegment.Religion.IsEmpty())
                    retVal.ReligiousAffiliation = pidSegment.Religion.ToModel(ReligionCodeSystem);

                // Ethinic groups
                fieldNo = 22;
                if (pidSegment.EthnicGroupRepetitionsUsed > 0)
                    retVal.EthnicGroupCodeKey = pidSegment.GetEthnicGroup().First().ToModel(EthnicGroupCodeSystem).Key;

                fieldNo = 18;
                // Patient account, locate the specified account
                if (!pidSegment.PatientAccountNumber.IsEmpty())
                {

                    var account = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Account>>()?.Query(o => o.Identifiers.Any(i => i.Value == pidSegment.PatientAccountNumber.IDNumber.Value), AuthenticationContext.SystemPrincipal).FirstOrDefault();
                    if (account != null)
                        retVal.Participations.Add(new ActParticipation(ActParticipationKey.Holder, retVal) { SourceEntityKey = account.Key });
                    else
                    {
                        retVal.Participations.Add(new ActParticipation(ActParticipationKey.Holder, retVal)
                        {
                            SourceEntity = new Account()
                            {
                                Identifiers = new List<ActIdentifier>()
                                {
                                    new ActIdentifier()
                                    {
                                        Authority = pidSegment.PatientAccountNumber.AssigningAuthority.ToModel(),
                                        Value = pidSegment.PatientAccountNumber.IDNumber.Value
                                    }
                                },
                                StatusConceptKey = StatusKeys.Active
                            }
                        });
                    }
                }

                // SSN
                fieldNo = 19;

                // Patient account, locate the specified account
                if (!String.IsNullOrEmpty(pidSegment.SSNNumberPatient.Value))
                {
                    var ssn = pidSegment.SSNNumberPatient.Value;
                    // Lookup identity domain which is designated as SSN , if they already have one update it, if not, add it
                    var existing = retVal.Identifiers.FirstOrDefault(o => o.Authority.DomainName == this.m_configuration.SsnAuthority?.DomainName);
                    if (existing == null)
                        retVal.Identifiers.Add(new EntityIdentifier(this.m_configuration.SsnAuthority, ssn));
                    else
                        existing.Value = ssn;
                }

                // Birth place is present
                fieldNo = 23;
                if (!pidSegment.BirthPlace.IsEmpty()) // We need to find the birthplace relationship
                {
                    var existing = retVal.Relationships.FirstOrDefault(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Birthplace);

                    if (Guid.TryParse(pidSegment.BirthPlace.Value, out Guid birthPlaceId))
                    {
                        if (existing == null)
                            retVal.Relationships.Add(new EntityRelationship(EntityRelationshipTypeKeys.Birthplace, birthPlaceId));
                        else
                            existing.TargetEntityKey = birthPlaceId;
                    }
                    else
                    {
                        var places = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Place>>()?.Query(o => o.Names.Any(n => n.Component.Any(c => c.Value == pidSegment.BirthPlace.Value)), AuthenticationContext.SystemPrincipal);
                        if (this.m_configuration.BirthplaceClassKeys.Any())
                            places = places.Where(o =>
                                this.m_configuration.BirthplaceClassKeys.Contains(o.ClassConceptKey.Value));

                        // Still conflicts? Check for same region as address
                        if (places.Count() > 1 && !this.m_configuration.StrictMetadataMatch)
                        {
                            var placeClasses = places.GroupBy(o=>o.ClassConceptKey).OrderBy(o => Array.IndexOf(AddressHierarchy, o.Key.Value));
                            // Take the first wrung of the address hierarchy
                            places = placeClasses.First();
                            if(places.Count() > 1) // Still more than one type of place
                                places = places.Where(p => p.LoadCollection<EntityAddress>(nameof(Entity.Addresses)).Any(a => a.Component.All(a2 => retVal.LoadCollection<EntityAddress>(nameof(Entity.Addresses)).Any(pa => pa.Component.Any(pc => pc.Value == a2.Value && pc.ComponentTypeKey == a2.ComponentTypeKey)))));
                        }

                        // Assign if only one place
                        if (places.Count() == 1)
                        {
                            if (existing == null)
                                retVal.Relationships.Add(new EntityRelationship(EntityRelationshipTypeKeys.Birthplace, places.First().Key));
                            else
                                existing.TargetEntityKey = places.First().Key;
                        }
                        else
                            throw new KeyNotFoundException($"Cannot find unique birth place registration with name {pidSegment.BirthPlace.Value} ({places.Count()} results found). Try using UUID.");
                    }
                }

                // MB indicator
                if (!pidSegment.MultipleBirthIndicator.IsEmpty())
                    retVal.MultipleBirthOrder = pidSegment.MultipleBirthIndicator.Value == "Y" ? (int?)-1 : null;
                if (!pidSegment.BirthOrder.IsEmpty())
                    retVal.MultipleBirthOrder = Int32.Parse(pidSegment.BirthOrder.Value);

                // Citizenship
                fieldNo = 26;
                if (pidSegment.CitizenshipRepetitionsUsed > 0)
                {
                    foreach (var cit in pidSegment.GetCitizenship())
                    {
                        var places = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Place>>()?.Query(o => o.Identifiers.Any(i => i.Value == cit.Identifier.Value && i.Authority.Key == AssigningAuthorityKeys.Iso3166CountryCode), AuthenticationContext.SystemPrincipal);
                        if (places.Count() == 1)
                            retVal.Relationships.Add(new EntityRelationship(EntityRelationshipTypeKeys.Citizen, places.First().Key));
                        else
                            throw new KeyNotFoundException($"Cannot find country with code {cit.Identifier.Value}");

                    }
                }

                // Death info
                fieldNo = 29;
                if (!pidSegment.PatientDeathIndicator.IsEmpty())
                    retVal.DeceasedDate = pidSegment.PatientDeathIndicator.Value == "Y" ? (DateTime?)DateTime.MinValue : null;
                if (!pidSegment.PatientDeathDateAndTime.IsEmpty())
                {
                    retVal.DeceasedDate = pidSegment.PatientDeathDateAndTime.ToModel();
                    retVal.DeceasedDatePrecision = pidSegment.PatientDeathDateAndTime.ToDatePrecision();
                }

                // Last update time
                if (!pidSegment.LastUpdateDateTime.IsEmpty())
                    retVal.CreationTime = (DateTimeOffset)pidSegment.LastUpdateDateTime.ToModel();

                //if(!pidSegment.LastUpdateFacility.IsEmpty())
                //{
                //    // Find by user ID
                //    var user = ApplicationServiceContext.Current.GetService<IDataPersistenceService<SecurityUser>>().Query(u=>u.UserName == pidSegment.LastUpdateFacility.NamespaceID.Value).FirstOrDefault();
                //    if (user != null)
                //        retVal.CreatedBy = user;
                //}

                if (motherEntity != null)
                    retCollection.Add(motherEntity);
                retCollection.Add(retVal);
                return retCollection;
            }
            catch (HL7ProcessingException e) // Just re-throw
            {
                throw;
            }
            catch (HL7DatatypeProcessingException e)
            {
                throw new HL7ProcessingException("Error processing PID segment", "PID", pidSegment.SetIDPID.Value, fieldNo, e.Component, e);
            }
            catch (Exception e)
            {
                throw new HL7ProcessingException("Error processing PID segment", "PID", pidSegment.SetIDPID.Value, fieldNo, 1, e);
            }
        }
    }
}
