using NUnit.Framework;
using SanteDB.Core.Model.Security;
using SanteDB.Core.Security;
using SanteDB.Core.Services;
using SanteDB.Core.TestFramework;
using SanteDB.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NHapi.Model.V25.Datatype;
using System.Security;
using SanteDB.Core.Model.Constants;
using SanteDB.Messaging.HL7.Exceptions;

namespace SanteDB.Messaging.HL7.Test
{
    [ExcludeFromCodeCoverage]
    [TestFixture(Category = "Unit")]
    public class DataConverterTests : DataTest
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
            var p = FirebirdSql.Data.FirebirdClient.FbCharset.Ascii;
            TestApplicationContext.TestAssembly = typeof(TestMessageParsing).Assembly;
            TestApplicationContext.Initialize(TestContext.CurrentContext.TestDirectory);

            // Create the test harness device / application
            var securityDevService = ApplicationServiceContext.Current.GetService<IRepositoryService<SecurityDevice>>();
            var securityAppService = ApplicationServiceContext.Current.GetService<IRepositoryService<SecurityApplication>>();
            var metadataService = ApplicationServiceContext.Current.GetService<IAssigningAuthorityRepositoryService>();
            this.m_serviceManager = ApplicationServiceContext.Current.GetService<IServiceManager>();

            AuthenticationContext.EnterSystemContext();

            // Create device
            var dev = new SecurityDevice()
            {
                DeviceSecret = "DEVICESECRET",
                Name = "TEST_HARNESS|TEST"
            };

            dev.AddPolicy(PermissionPolicyIdentifiers.LoginAsService);
            securityDevService.Insert(dev);

            // Create device
            dev = new SecurityDevice()
            {
                DeviceSecret = "DEVICESECRET",
                Name = "TEST_HARNESS|MASTER"
            };
            dev.AddPolicy(PermissionPolicyIdentifiers.LoginAsService);
            dev.AddPolicy("1.3.6.1.4.1.33349.3.1.5.9.2.6");
            securityDevService.Insert(dev);

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

            metadataService.Insert(new Core.Model.DataTypes.AssigningAuthority("SSN", "US Social Security Number", "2.16.840.1.113883.4.1")
            {
                IsUnique = false,
                Url = "http://hl7.org/fhir/sid/us-ssn",
                AssigningApplicationKey = app.Key
            });

            // Add another application for security checks
            dev = new SecurityDevice()
            {
                DeviceSecret = "DEVICESECRET2",
                Name = "TEST_HARNESS2|TEST"
            };

            dev.AddPolicy(PermissionPolicyIdentifiers.LoginAsService);
            securityDevService.Insert(dev);

            app = new SecurityApplication()
            {
                Name = "TEST_HARNESS2",
                ApplicationSecret = "APPLICATIONSECRET2"
            };

            app.AddPolicy(PermissionPolicyIdentifiers.LoginAsService);
            app.AddPolicy(PermissionPolicyIdentifiers.UnrestrictedClinicalData);
            app.AddPolicy(PermissionPolicyIdentifiers.ReadMetadata);
            securityAppService.Insert(app);
        }

        [Test]
        public void TestNullValue()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                XTN xtn = null;

                Assert.Throws<ArgumentNullException>(() => DataConverter.ToModel(xtn));

            }
        }

        [Test]
        public void TestEmpty_IsNotNull()
        {
            using (AuthenticationContext.EnterSystemContext()) {

                var xtn = new XTN(null);

                var dut = DataConverter.ToModel(xtn);

                Assert.NotNull(dut);
            }
        }

        [Test]
        public void TestEmpty_AddressUseIsNoInformation()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var xtn = new XTN(null);
                var dut = DataConverter.ToModel(xtn);

                Assert.AreEqual(NullReasonKeys.NoInformation, dut.AddressUseKey);
            }
        }

        [Test]
        public void TestEmpty_TypeConceptIsNoInformation()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var xtn = new XTN(null);
                var dut = DataConverter.ToModel(xtn);

                Assert.AreEqual(NullReasonKeys.NoInformation, dut.TypeConceptKey);
            }
        }

        [Test]
        public void TestMultipleValues_ShouldThrowHL7DatatypeProcessingException()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var xtn = new XTN(null);

                xtn.TelecommunicationEquipmentType.Value = "Internet";
                xtn.EmailAddress.Value = "test@example.com";
                xtn.UnformattedTelephoneNumber.Value = "1-555-555-1212";

                Assert.Throws<HL7DatatypeProcessingException>(() => DataConverter.ToModel(xtn));
            }
        }

        [Test]
        public void TestSingleValue_EmailAddress()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var xtn = new XTN(null);

                xtn.TelecommunicationEquipmentType.Value = "Internet";
                xtn.EmailAddress.Value = "test@example.com";

                var dut = DataConverter.ToModel(xtn);

                Assert.AreEqual(TelecomAddressTypeKeys.Internet, dut.TypeConceptKey);
                Assert.AreEqual("test@example.com", dut.Value);
            }
        }

        [Test]
        public void TestSingleValue_Delimited()
        {
            using (AuthenticationContext.EnterSystemContext())
            {
                var xtn = new XTN(null);

                xtn.TelecommunicationEquipmentType.Value = "PH";
                xtn.LocalNumber.Value = "555-1212";
                xtn.AreaCityCode.Value = "555";

                var dut = DataConverter.ToModel(xtn);

                Assert.AreEqual(TelecomAddressTypeKeys.Telephone, dut.TypeConceptKey);
                Assert.AreEqual("555555-1212", dut.Value);
            }

        }
    }
}
