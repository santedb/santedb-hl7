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
using NHapi.Base.Model;
using NHapi.Model.V25.Segment;
using SanteDB.Core;
using SanteDB.Core.Model.Constants;
using SanteDB.Core.Model.Roles;
using SanteDB.Core.Model.Security;
using SanteDB.Core.Security;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.Messages;
using SanteDB.Messaging.HL7.TransportProtocol;
using SanteDB.Core.TestFramework;
using System;
using System.Linq;
using NHapi.Model.V25.Message;
using SanteDB.Core.Model;
using SanteDB.Core.Model.Entities;
using NUnit.Framework;

namespace SanteDB.Messaging.HL7.Test
{
    [TestFixture(Category = "Integration")]
    public class TestMessageParsing : DataTest
    {

        /// <summary>
        /// Test context
        /// </summary>
        /// <param name="context"></param>
        [SetUp]
        public void Initialize()
        {
            // Force load of the DLL
            var p = FirebirdSql.Data.FirebirdClient.FbCharset.Ascii;
            TestApplicationContext.TestAssembly = typeof(TestMessageParsing).Assembly;
            TestApplicationContext.Initialize(TestContext.CurrentContext.TestDirectory);

            // Create the test harness device / application
            var securityDevService = ApplicationServiceContext.Current.GetService<IRepositoryService<SecurityDevice>>();
            var securityAppService = ApplicationServiceContext.Current.GetService<IRepositoryService<SecurityApplication>>();
            var metadataService = ApplicationServiceContext.Current.GetService<IAssigningAuthorityRepositoryService>();
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            // Create device
            var dev = new SecurityDevice()
            {
                DeviceSecret = "DEVICESECRET",
                Name = "TEST_HARNESS|TEST"
            };
            dev.AddPolicy(PermissionPolicyIdentifiers.LoginAsService);
            dev = securityDevService.Insert(dev);

            // Create device
            dev = new SecurityDevice()
            {
                DeviceSecret = "DEVICESECRET",
                Name = "TEST_HARNESS|MASTER"
            };
            dev.AddPolicy(PermissionPolicyIdentifiers.LoginAsService);
            dev.AddPolicy("1.3.6.1.4.1.33349.3.1.5.9.2.6");
            dev = securityDevService.Insert(dev);

            var app = new SecurityApplication()
            {
                Name = "TEST_HARNESS",
                ApplicationSecret = "APPLICATIONSECRET"
            };
            app.AddPolicy(PermissionPolicyIdentifiers.LoginAsService);
            app.AddPolicy(PermissionPolicyIdentifiers.UnrestrictedClinicalData);
            app.AddPolicy(PermissionPolicyIdentifiers.ReadMetadata);
            app = securityAppService.Insert(app);
            metadataService.Insert(new Core.Model.DataTypes.AssigningAuthority("TEST", "TEST", "1.2.3.4.5.6.7")
            {
                IsUnique = true,
                AssigningApplicationKey = app.Key
            });

            // Add another application for security checks
            dev = new SecurityDevice()
            {
                DeviceSecret = "DEVICESECRET2",
                Name = "TEST_HARNESS2|TEST"
            };
            dev.AddPolicy(PermissionPolicyIdentifiers.LoginAsService);
            dev = securityDevService.Insert(dev);

            app = new SecurityApplication()
            {
                Name = "TEST_HARNESS2",
                ApplicationSecret = "APPLICATIONSECRET2"
            };
            app.AddPolicy(PermissionPolicyIdentifiers.LoginAsService);
            app.AddPolicy(PermissionPolicyIdentifiers.UnrestrictedClinicalData);
            app.AddPolicy(PermissionPolicyIdentifiers.ReadMetadata);
            app = securityAppService.Insert(app);
        }

        /// <summary>
        /// Test that ADT message is parsed properly
        /// </summary>
        [Test]
        public void TestParseADTMessage()
        {
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            var msg = TestUtil.GetMessage("ADT_SIMPLE");
            var message = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var messageStr = TestUtil.ToString(message);
            Assert.AreEqual("CA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);

            // Ensure that the patient actually was persisted
            var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-1"), AuthenticationContext.Current.Principal).SingleOrDefault();
            Assert.IsNotNull(patient);
            Assert.IsTrue(messageStr.Contains(patient.Key.ToString()));
            Assert.AreEqual(1, patient.Names.Count);
            Assert.AreEqual("JOHNSTON", patient.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Family).Value);
            Assert.AreEqual("ROBERT", patient.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Given).Value);
        }

        /// <summary>
        /// Test that ADT message is parsed properly
        /// </summary>
        [Test]
        public void TestUpdateAdt()
        {
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            var msg = TestUtil.GetMessage("ADT_SIMPLE");
            var message = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var messageStr = TestUtil.ToString(message);
            Assert.AreEqual("CA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);

            var patientOriginal = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-1"), AuthenticationContext.Current.Principal).SingleOrDefault();

            msg = TestUtil.GetMessage("ADT_UPDATE");
            message = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            messageStr = TestUtil.ToString(message);
            Assert.AreEqual("CA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);

            // Ensure that the patient actually was persisted
            var patientNew = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-1"), AuthenticationContext.Current.Principal).SingleOrDefault();
            Assert.IsNotNull(patientNew);
            Assert.IsTrue(messageStr.Contains(patientNew.Key.ToString()));
            Assert.AreEqual(1, patientNew.Names.Count);
            Assert.AreEqual("JOHNSTON", patientNew.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Family).Value);
            Assert.AreEqual("ROBERTA", patientNew.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Given).Value);
        }

        /// <summary>
        /// Test that ADT message is parsed properly
        /// </summary>
        [Test]
        public void TestParseComplexADTMessage()
        {
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            var msg = TestUtil.GetMessage("ADT_PD1");
            var message = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var messageStr = TestUtil.ToString(message);
            Assert.AreEqual("CA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);

            // Ensure that the patient actually was persisted
            var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-2"), AuthenticationContext.Current.Principal).SingleOrDefault();
            Assert.IsNotNull(patient);
            Assert.IsTrue(messageStr.Contains(patient.Key.ToString()));
            Assert.AreEqual(1, patient.Names.Count);
            Assert.AreEqual("JOHNSTON", patient.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Family).Value);
            Assert.AreEqual("ROBERT", patient.Names.First().Component.First(o => o.ComponentTypeKey == NameComponentKeys.Given).Value);
            Assert.AreEqual(1, patient.Relationships.Count(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Birthplace));
            Assert.AreEqual(1, patient.Relationships.Count(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Father));
            Assert.AreEqual(1, patient.Relationships.Count(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Mother));
            Assert.AreEqual(2, patient.Relationships.Count(o => o.RelationshipTypeKey == EntityRelationshipTypeKeys.Citizen));
            Assert.AreEqual(1, patient.Policies.Count);
           
        }

        /// <summary>
        /// Tests that a query actually occurs
        /// </summary>
        [Test]
        public void TestParseQBPMessage()
        {
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            var msg = TestUtil.GetMessage("QBP_SIMPLE_PRE");
            new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-3"), AuthenticationContext.Current.Principal).SingleOrDefault();
            Assert.IsNotNull(patient);
            msg = TestUtil.GetMessage("QBP_SIMPLE");
            var message = new QbpMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var messageStr = TestUtil.ToString(message);
            Assert.AreEqual("SMITH", ((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetMotherSMaidenName(0).FamilyName.Surname.Value);
            Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
            Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
            Assert.AreEqual("K22", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);
        }

        /// <summary>
        /// Tests that a query actually occurs
        /// </summary>
        [Test]
        public void TestParseComplexQBPMessage()
        {
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            var msg = TestUtil.GetMessage("QBP_COMPLEX_PRE");
            new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-9"), AuthenticationContext.Current.Principal).SingleOrDefault();
            Assert.IsNotNull(patient);
            Assert.AreEqual(6, patient.LoadCollection<EntityRelationship>(nameof(Entity.Relationships)).Count());
            Assert.IsNotNull(patient.LoadCollection<EntityRelationship>(nameof(Entity.Relationships)).FirstOrDefault(o=>o.RelationshipTypeKey == EntityRelationshipTypeKeys.Mother));
            msg = TestUtil.GetMessage("QBP_COMPLEX");
            var message = new QbpMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var messageStr = TestUtil.ToString(message);
            Assert.AreEqual("SMITH", ((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetMotherSMaidenName(0).FamilyName.Surname.Value, $"Mothers name doesn't match {messageStr}");
            Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
            Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
            Assert.AreEqual("K22", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);
        }


        /// <summary>
        /// Tests that a query actually occurs
        /// </summary>
        [Test]
        public void TestParseAndQBPMessage()
        {
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            var msg = TestUtil.GetMessage("QBP_COMPLEX_PRE");
            var response = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-9"), AuthenticationContext.Current.Principal).SingleOrDefault();
            Assert.IsNotNull(patient);
            msg = TestUtil.GetMessage("QBP_AND_PRE");
            new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-10"), AuthenticationContext.Current.Principal).SingleOrDefault();
            Assert.IsNotNull(patient);

            msg = TestUtil.GetMessage("QBP_COMPLEX");
            var message = new QbpMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var messageStr = TestUtil.ToString(message);
            Assert.AreEqual("1", (message.GetStructure("QAK") as QAK).HitCount.Value);
            Assert.AreEqual("SMITH", ((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetMotherSMaidenName(0).FamilyName.Surname.Value);
            Assert.AreNotEqual("JENNY", ((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetPatientName(0).GivenName.Value);
            Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
            Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
            Assert.AreEqual("K22", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);

            // OR MESSAGE SHOULD CATCH TWO PATIENTS
            msg = TestUtil.GetMessage("QBP_OR");
            message = new QbpMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            messageStr = TestUtil.ToString(message);
            Assert.AreEqual("2", (message.GetStructure("QAK") as QAK).HitCount.Value);
            Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
            Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
            Assert.AreEqual("K22", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);
        }
        /// <summary>
        /// Tests that the error code and location are appropriate for the type of error that is encountered
        /// </summary>
        [Test]
        public void TestErrorLocation()
        {
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            var msg = TestUtil.GetMessage("ADT_INV_GC");
            var errmsg = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var messageStr = TestUtil.ToString(errmsg);

            var ack = errmsg as ACK;
            Assert.AreNotEqual(0, ack.ERRRepetitionsUsed);
            Assert.AreEqual("204", ack.GetERR(0).HL7ErrorCode.Identifier.Value);
            Assert.AreEqual("8", ack.GetERR(0).GetErrorLocation(0).FieldPosition.Value);
            Assert.AreEqual("PID", ack.GetERR(0).GetErrorLocation(0).SegmentID.Value);
            Assert.AreEqual("1", ack.GetERR(0).GetErrorLocation(0).SegmentSequence.Value);

        }

        /// <summary>
        /// Tests that a query actually occurs
        /// </summary>
        [Test]
        public void TestCrossReference()
        {
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            var msg = TestUtil.GetMessage("QBP_XREF_PRE");
            var result = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var patient = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "HL7-4"), AuthenticationContext.Current.Principal).SingleOrDefault();
            Assert.IsNotNull(patient);
            msg = TestUtil.GetMessage("QBP_XREF");
            var message = new QbpMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var messageStr = TestUtil.ToString(message);
            // TODO : Assert that id is present
            Assert.IsTrue(((message.GetStructure("QUERY_RESPONSE") as AbstractGroup).GetStructure("PID") as PID).GetPatientIdentifierList().Any(i => i.IDNumber.Value == patient.Key.ToString() && i.AssigningAuthority.NamespaceID.Value == "KEY"));
            Assert.AreEqual("AA", (message.GetStructure("MSA") as MSA).AcknowledgmentCode.Value);
            Assert.AreEqual("OK", (message.GetStructure("QAK") as QAK).QueryResponseStatus.Value);
            Assert.AreEqual("K23", (message.GetStructure("MSH") as MSH).MessageType.TriggerEvent.Value);
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
            AuthenticationContext.Current = new AuthenticationContext(AuthenticationContext.SystemPrincipal);
            var msg = TestUtil.GetMessage("ADT_MRG_PRE1");
            var result = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            var resultStr = TestUtil.ToString(result);
            Assert.IsTrue(resultStr.Contains("|CA"));
            Assert.AreEqual(1, patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-439")).Count());
            var patientA = patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-439")).SingleOrDefault();

            // Register second patient
            msg = TestUtil.GetMessage("ADT_MRG_PRE2");
            result = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            resultStr = TestUtil.ToString(result);
            Assert.IsTrue(resultStr.Contains("|CA"));
            Assert.AreEqual(1, patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-999")).Count());
            var patientB = patientRepository.Find(o => o.Identifiers.Any(id => id.Value == "RJ-999")).SingleOrDefault();

            // There are 2 patients
            var patients = ApplicationServiceContext.Current.GetService<IDataPersistenceService<Patient>>().Query(o => o.Identifiers.Any(i => i.Value == "RJ-439" || i.Value == "RJ-999"), AuthenticationContext.Current.Principal);
            Assert.AreEqual(2, patients.Count());

            msg = TestUtil.GetMessage("ADT_MRG");
            result = new AdtMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            resultStr = TestUtil.ToString(result);
            Assert.IsTrue(resultStr.Contains("|CA"));

            // Validate QBP appropriately redirects as described in 3.6.2.1.2
            msg = TestUtil.GetMessage("ADT_MRG_POST");
            result = new QbpMessageHandler().HandleMessage(new Hl7MessageReceivedEventArgs(msg, new Uri("test://"), new Uri("test://"), DateTime.Now));
            resultStr = TestUtil.ToString(result);
            Assert.IsTrue(resultStr.Contains("|AA"));
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
            Assert.AreEqual(StatusKeys.Obsolete, oldMaster.StatusConceptKey); // Old Master is obsolete


            
        }

    }
}
