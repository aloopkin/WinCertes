using System;
using System.Collections.Generic;
using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WinCertes;

namespace WinCertes.Tests
{
    [TestClass()]
    public class UtilsTest
    {
        [TestMethod()]
        public void DomainsToHostIdTest()
        {
            List<string> domains = new List<string>();
            domains.Add("test2.example.com");
            domains.Add("test.example.com");
            domains.Sort();
            string hostId = Utils.DomainsToHostId(domains);
            if (!hostId.Equals("_6fb23d16b162f18a")) {
                // we're not ok
                Assert.Fail();
            }
        }

        [TestMethod()]
        public void IsAdministratorTest()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (principal.IsInRole(WindowsBuiltInRole.Administrator) != Utils.IsAdministrator()) {
                Assert.Fail();
            }
        }

        [TestMethod()]
        public void KeyGenerationTest()
        {
            string keyPem = Utils.GenerateRSAKeyAsPEM(2048);
            if (!keyPem.Contains("BEGIN"))
                Assert.Fail();
        }
    }
}

namespace WinCertes.Test
{
    [TestClass]
    public class UtilsTest
    {
        [TestMethod]
        public void DomainsToFriendlyNameTest()
        {
            List<string> domains = new List<string>();
            domains.Add("test2.example.com");
            domains.Add("test.example.com");
            domains.Sort();
            string friendlyName = Utils.DomainsToFriendlyName(domains);
            if (!friendlyName.Equals("testexamplecom00")) {
                // we're not ok
                Assert.Fail();
            }
        }
    }
}
