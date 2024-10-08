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
using NHapi.Model.V25.Message;
using NHapi.Model.V25.Segment;
using NUnit.Framework;
using SanteDB.Core;
using SanteDB.Core.Model;
using SanteDB.Core.Model.Constants;
using SanteDB.Core.Model.Entities;
using SanteDB.Core.Model.Roles;
using SanteDB.Core.Model.Security;
using SanteDB.Core.Security;
using SanteDB.Core.Security.Services;
using SanteDB.Core.Services;
using SanteDB.Core.TestFramework;
using SanteDB.Messaging.HL7.Messages;
using SanteDB.Messaging.HL7.TransportProtocol;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace SanteDB.Messaging.HL7.Test
{
    [ExcludeFromCodeCoverage]
    [TestFixture(Category = "Integration")]
    public class TestMessageParsing : DataTest
    {
        private IServiceManager m_serviceManager;

        /// <summary>
        /// Test context
        /// </summary>
        /// <param name="context"></param>
        [OneTimeSetUp]
        public void Initialize()
        {
            // Force load of the DLL
            TestApplicationContext.TestAssembly = typeof(TestMessageParsing).Assembly;
            TestApplicationContext.Initialize(TestContext.CurrentContext.TestDirectory);

            // Create the test harness device / application
            var securityDevService = ApplicationServiceContext.Current.GetService<IRepositoryService<SecurityDevice>>();
            var securityAppService = ApplicationServiceContext.Current.GetService<IRepositoryService<SecurityApplication>>();
            var pipService = ApplicationServiceContext.Current.GetService<IPolicyInformationService>();
            var metadataService = ApplicationServiceContext.Current.GetService<IIdentityDomainRepositoryService>();
            var placeService = ApplicationServiceContext.Current.GetService<IRepositoryService<Place>>();
            this.m_serviceManager = ApplicationServiceContext.Current.GetService<IServiceManager>();

            AuthenticationContext.EnterSystemContext();

            // Create good health hospital if it does not already exist
            if (!placeService.Find(o => o.Names.Any(n => n.Component.Any(c => c.Value == "Good Health Hospital"))).Any())
            {
                placeService.Insert(new Place()
                {
                    Key = Guid.Parse("fd0d2a08-8e94-402b-84b6-cb3bc0a576a9"),
                    ClassConceptKey = EntityClassKeys.ServiceDeliveryLocation,
                    DeterminerConceptKey = DeterminerKeys.Specific,
                    Names = new System.Collections.Generic.List<EntityName>()
                    {
                        new EntityName(NameUseKeys.OfficialRecord, "Good Health Hospital")
                    }
                });
            }

            // Create device
            var dev = new SecurityDevice()
            {
                DeviceSecret = "DEVICESECRET",
                Name = "TEST_HARNESS|TEST"
            };
            if (!securityDevService.Find(o => o.Name == dev.Name).Any())
            {
                dev = securityDevService.Insert(dev);
                pipService.AddPolicies(dev, PolicyGrantType.Grant, AuthenticationContext.SystemPrincipal, PermissionPolicyIdentifiers.LoginAsService, PermissionPolicyIdentifiers.UnrestrictedClinicalData, PermissionPolicyIdentifiers.ReadMetadata);
            }

            // Create device
            dev = new SecurityDevice()
            {
                DeviceSecret = "DEVICESECRET",
                Name = "TEST_HARNESS|MASTER"
            };
            if (!securityDevService.Find(o => o.Name == dev.Name).Any())
            {
                dev = securityDevService.Insert(dev);
                pipService.AddPolicies(dev, PolicyGrantType.Grant, AuthenticationContext.SystemPrincipal, PermissionPolicyIdentifiers.UnrestrictedAll, "1.3.6.1.4.1.33349.3.1.5.9.2.6");
            }

            var app = new SecurityApplication()
            {
                Name = "TEST_HARNESS",
                ApplicationSecret = "APPLICATIONSECRET"
            };
            if (!securityAppService.Find(o => o.Name == dev.Name).Any())
            {
                app = securityAppService.Insert(app);
                pipService.AddPolicies(app, PolicyGrantType.Grant, AuthenticationContext.SystemPrincipal, PermissionPolicyIdentifiers.LoginAsService, PermissionPolicyIdentifiers.UnrestrictedClinicalData, PermissionPolicyIdentifiers.ReadMetadata);
                metadataService.Insert(new Core.Model.DataTypes.IdentityDomain("TEST", "TEST", "1.2.3.4.5.6.7")
                {
                    IsUnique = true,
                    AssigningAuthority = new System.Collections.Generic.List<Core.Model.DataTypes.AssigningAuthority>()
                {
                    new Core.Model.DataTypes.AssigningAuthority()
                    {
                        AssigningApplicationKey = app.Key,
                        Reliability = Core.Model.DataTypes.IdentifierReliability.Authoritative
                    }
                }
                });
            }


            // Add another application for security checks
            dev = new SecurityDevice()
            {
                DeviceSecret = "DEVICESECRET2",
                Name = "TEST_HARNESS2|TEST"
            };
            if (!securityDevService.Find(o => o.Name == dev.Name).Any())
            {
                dev = securityDevService.Insert(dev);
                pipService.AddPolicies(dev, PolicyGrantType.Grant, AuthenticationContext.SystemPrincipal, PermissionPolicyIdentifiers.LoginAsService);
            }

            app = new SecurityApplication()
            {
                Name = "TEST_HARNESS2",
                ApplicationSecret = "APPLICATIONSECRET2"
            };
            if (!securityAppService.Find(o => o.Name == dev.Name).Any())
            {
                app = securityAppService.Insert(app);
                pipService.AddPolicies(dev, PolicyGrantType.Grant, AuthenticationContext.SystemPrincipal, PermissionPolicyIdentifiers.LoginAsService);
            }
        }

        /// <summary>
        /// Test that ADT message is parsed properly
        /// </summary>
        [Test]
        public void TestParseADTMessage()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var msg = TestUtil.GetMessage("ADT_SIMPLE");
                var message = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                var messageStr = TestUtil.ToString(message);
                Assert.AreEqual("CA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value, "RQ: {0}, RS: {1}", TestUtil.ToString(msg), messageStr);

                // Ensure that the patient actually was persisted
                var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-1"), AuthenticationContext.Current.Principal).SingleOrDefault();
                Assert.IsNotNull(patient);
                Assert.IsTrue(messageStr.Contains(patient.Key.ToString()));
                Assert.AreEqual(1, patient.LoadProperty(o=>o.Names).Count);
                Assert.AreEqual("JOHNSTON", patient.Names.First().LoadProperty(o=>o.Component).First(o => o.ComponentTypeKey == NameComponentKeys.Family).Value);
                Assert.AreEqual("ROBERT", patient.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Given).Value);
            }
        }

        /// <summary>
        /// Test that ADT message is parsed properly
        /// </summary>
        [Test]
        public void TestUpdateAdt()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var msg = TestUtil.GetMessage("ADT_SIMPLE");
                var message = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                var messageStr = TestUtil.ToString(message);

                Assert.AreEqual("CA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value, "RQ: {0}, RS: {1}", TestUtil.ToString(msg), messageStr);

                var patientOriginal = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-1"), AuthenticationContext.Current.Principal).SingleOrDefault();

                Assert.NotNull(patientOriginal);

                msg = TestUtil.GetMessage("ADT_UPDATE");
                message = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                messageStr = TestUtil.ToString(message);

                Assert.AreEqual("CA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value, "RQ: {0}, RS: {1}", TestUtil.ToString(msg), messageStr);

                // Ensure that the patient actually was persisted
                var patientNew = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-1"), AuthenticationContext.Current.Principal).SingleOrDefault();

                Assert.IsNotNull(patientNew);
                Assert.AreEqual(1, patientNew.Names.Count);
                Assert.AreEqual("JOHNSTON", patientNew.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Family).Value);
                Assert.AreEqual("ROBERTA", patientNew.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Given).Value);
            }
        }

        /// <summary>
        /// Test that ADT message is parsed properly
        /// </summary>
        [Test]
        public void TestParseComplexADTMessage()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var msg = TestUtil.GetMessage("ADT_PD1");
                var message = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                var messageStr = TestUtil.ToString(message);
                Assert.AreEqual("CA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value, "RQ: {0}, RS: {1}", TestUtil.ToString(msg), messageStr);

                // Ensure that the patient actually was persisted
                var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-2"), AuthenticationContext.Current.Principal).SingleOrDefault();
                Assert.IsNotNull(patient);
                Assert.IsTrue(messageStr.Contains(patient.Key.ToString()));
                Assert.AreEqual(1, patient.LoadProperty(o=>o.Names).Count);
                Assert.AreEqual("JOHNSTON", patient.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Family).Value);
                Assert.AreEqual("ROBERT", patient.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Given).Value);
                Assert.AreEqual(1, patient.Relationships.Count(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Birthplace));
                Assert.AreEqual(1, patient.Relationships.Count(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Father));
                Assert.AreEqual(1, patient.Relationships.Count(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Mother));
                Assert.AreEqual(2, patient.Relationships.Count(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Citizen));
                Assert.AreEqual(1, patient.Policies.Count);
            }
        }

        /// <summary>
        /// Tests that a query actually occurs
        /// </summary>
        [Test]
        public void TestParseQBPMessage()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var msg = TestUtil.GetMessage("QBP_SIMPLE_PRE");
                this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-3"), AuthenticationContext.Current.Principal).SingleOrDefault();
                Assert.IsNotNull(patient);
                msg = TestUtil.GetMessage("QBP_SIMPLE");
                var message = this.m_serviceManager.CreateInjected<QbpMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                Assert.AreEqual("SMITH", ((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetMotherSMaidenName(0).FamilyName.Surname.Value);
                Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
                Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
                Assert.AreEqual("K22", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);
            }
        }

        /// <summary>
        /// Tests that a query actually occurs
        /// </summary>
        [Test]
        public void TestParseComplexQBPMessage()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var patientRepo = ApplicationServiceContext.Current.GetService<IRepositoryService<Patient>>();
                var msg = TestUtil.GetMessage("QBP_COMPLEX_PRE");
                var response = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                Assert.AreEqual("CA", (response.GetStructure("MSA") as MSA).AcknowledgmentCode.Value, "RQ: {0}, RS: {1}", TestUtil.ToString(msg), TestUtil.ToString(response));
                var patient = patientRepo.Find(o => o.Identifiers.Any(i => i.Value == "HL7-9")).SingleOrDefault();
                Assert.IsNotNull(patient);
                Assert.AreEqual(9, patient.LoadCollection<EntityRelationship>(nameof(Entity.Relationships)).Count());
                Assert.IsNotNull(patient.LoadCollection<EntityRelationship>(nameof(Entity.Relationships)).FirstOrDefault(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Mother));
                msg = TestUtil.GetMessage("QBP_COMPLEX");
                var message = this.m_serviceManager.CreateInjected<QbpMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                var messageStr = TestUtil.ToString(message);
                Assert.AreEqual("SMITH", ((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetMotherSMaidenName(0).FamilyName.Surname.Value, $"Mothers name doesn't match {messageStr}");
                Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
                Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
                Assert.AreEqual("K22", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);
            }
        }

        /// <summary>
        /// Tests that a query actually occurs
        /// </summary>
        [Test]
        public void TestParseAndQBPMessage()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var msg = TestUtil.GetMessage("QBP_COMPLEX_PRE");
                var response = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-9"), AuthenticationContext.Current.Principal).SingleOrDefault();
                Assert.IsNotNull(patient);
                msg = TestUtil.GetMessage("QBP_AND_PRE");
                this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-10"), AuthenticationContext.Current.Principal).SingleOrDefault();
                Assert.IsNotNull(patient);

                msg = TestUtil.GetMessage("QBP_COMPLEX");
                var message = this.m_serviceManager.CreateInjected<QbpMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                var messageStr = TestUtil.ToString(message);
                Assert.AreEqual("1", (message.GetStructure("QAK") as QAK).HitCount.Value);
                Assert.AreEqual("SMITH", ((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetMotherSMaidenName(0).FamilyName.Surname.Value);
                Assert.AreNotEqual("JENNY", ((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetPatientName(0).GivenName.Value);
                Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
                Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
                Assert.AreEqual("K22", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);

                // OR MESSAGE SHOULD CATCH TWO PATIENTS
                msg = TestUtil.GetMessage("QBP_OR");
                message = this.m_serviceManager.CreateInjected<QbpMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                messageStr = TestUtil.ToString(message);
                Assert.AreEqual("2", (message.GetStructure("QAK") as QAK).HitCount.Value);
                Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
                Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
                Assert.AreEqual("K22", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);
            }
        }

        /// <summary>
        /// Tests that the error code and location are appropriate for the type of error that is encountered
        /// </summary>
        [Test]
        public void TestErrorLocation()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var msg = TestUtil.GetMessage("ADT_INV_GC");
                var errmsg = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));

                var ack = errmsg as ACK;
                Assert.AreNotEqual(0, ack.ERRRepetitionsUsed);
                Assert.AreEqual("204", ack.GetERR(0).HL7ErrorCode.Identifier.Value);
                Assert.AreEqual("8", ack.GetERR(0).GetErrorLocation(0).FieldPosition.Value);
                Assert.AreEqual("PID", ack.GetERR(0).GetErrorLocation(0).SegmentID.Value);
                Assert.AreEqual("1", ack.GetERR(0).GetErrorLocation(0).SegmentSequence.Value);
            }
        }

        /// <summary>
        /// Tests that a query actually occurs
        /// </summary>
        [Test]
        public void TestCrossReference()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var msg = TestUtil.GetMessage("QBP_XREF_PRE");
                var result = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                Assert.AreEqual("CA", (result.GetStructure("MSA") as MSA).AcknowledgmentCode.Value, "RQ: {0}, RS: {1}", TestUtil.ToString(msg), TestUtil.ToString(result));
                var patient = ApplicationServiceContext.Current.GetService<IRepositoryService<Patient>>().Find(o => o.Identifiers.Any(i => i.Value == "HL7-4")).SingleOrDefault();
                Assert.IsNotNull(patient);
                msg = TestUtil.GetMessage("QBP_XREF");
                var message = this.m_serviceManager.CreateInjected<QbpMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                var messageStr = TestUtil.ToString(message);
                // TODO : Assert that id is present
                Assert.IsTrue(((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetPatientIdentifierList().Any(i => i.IDNumber.Value == patient.Key.ToString() && i.AssigningAuthority.NamespaceID.Value == "KEY"));
                Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
                Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
                Assert.AreEqual("K23", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);
            }
        }

        /// <summary>
        /// Tests that the MRG appropriately behaves according to HL7 SPEC
        /// </summary>
        /// <remarks>
        /// This test does not take into consideration MDM use cases such as MASTER->MASTER or LOCAL->LOCAL, it
        /// merely tests that at the interface level, the old identifier for a patient (QBP) results in
        /// the new redirected object being returned
        /// </remarks>
        [Test]
        public void TestMerge()
        {
            var entityRepository = ApplicationServiceContext.Current.GetService<IRepositoryService<Entity>>();
            var patientRepository = ApplicationServiceContext.Current.GetService<IRepositoryService<Patient>>();

            // Register first patient
            using (AuthenticationContext.EnterSystemContext())
            {
                var msg = TestUtil.GetMessage("ADT_MRG_PRE1");
                var result = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                var resultStr = TestUtil.ToString(result);
                Assert.IsTrue(resultStr.Contains("|CA"));
                Assert.AreEqual(1, patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-439")).Count());
                var patientA = patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-439")).SingleOrDefault();

                // Register second patient
                msg = TestUtil.GetMessage("ADT_MRG_PRE2");
                result = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                resultStr = TestUtil.ToString(result);
                Assert.IsTrue(resultStr.Contains("|CA"));
                Assert.AreEqual(1, patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-999")).Count());
                var patientB = patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-999")).SingleOrDefault();

                // There are 2 patients
                var patients = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "RJ-439" || i.Value == "RJ-999"), AuthenticationContext.Current.Principal);
                Assert.AreEqual(2, patients.Count());

                msg = TestUtil.GetMessage("ADT_MRG");
                result = this.m_serviceManager.CreateInjected<AdtMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                resultStr = TestUtil.ToString(result);
                Assert.IsTrue(resultStr.Contains("|CA"), resultStr);

                // Validate QBP appropriately redirects as described in 3.6.2.1.2
                msg = TestUtil.GetMessage("ADT_MRG_POST");
                result = this.m_serviceManager.CreateInjected<QbpMessageHandler>().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
                resultStr = TestUtil.ToString(result);
                Assert.IsTrue(resultStr.Contains("|AA"), resultStr);
                Assert.IsTrue(resultStr.Contains("RJ-439"), "Missing Patient A identifier");
                Assert.IsTrue(resultStr.Contains("RJ-999"), "Missing Patient B identifier");
                Assert.IsTrue(resultStr.Contains(patientA.Key.ToString()), "Missing Master Key for Patient A");
                Assert.IsFalse(resultStr.Contains(patientB.Key.ToString()), "Should not have Master Key for Patient B");

                // Validate -> Query for RJ-439 resolves to patient
                var afterMergeA = patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-439")).SingleOrDefault();
                Assert.AreEqual(patientA.Key, afterMergeA.Key); // Remains unchanged (Patient A => After Merge A)

                // Validate -> Query for RJ-999 resolves to same patient
                var afterMergeB = patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-999")).SingleOrDefault();
                Assert.AreNotEqual(patientB.Key, afterMergeB.Key); // (Patient B no longer equals Merge B since it was merged into A)
                Assert.AreEqual(patientA.Key, afterMergeB.Key); // Patient B => Patient A
                var oldMaster = entityRepository.Get(patientB.Key.Value);
                oldMaster.LoadProperty(o => o.StatusConcept);
                Assert.IsNotNull(oldMaster.ObsoletionTime);
            }
        }
    }
}