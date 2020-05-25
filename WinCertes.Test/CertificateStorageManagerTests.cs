using Microsoft.VisualStudio.TestTools.UnitTesting;
using WinCertes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace WinCertes.Tests
{
    [TestClass()]
    public class CertificateStorageManagerTests
    {
        [TestMethod()]
        public void ProcessPFXTest()
        {
            var pfxName = Environment.GetEnvironmentVariable("TEMP")+"\\test_tmp.pfx";
            var pfxPwd = "test";
            var testPfx = "MIII4QIBAzCCCKcGCSqGSIb3DQEHAaCCCJgEggiUMIIIkDCCA0cGCSqGSIb3DQEHBqCCAzgwggM0AgEAMIIDLQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIA8LIxLUYVCsCAggAgIIDAMjaS/s4uR/FK7lYpSBe3QamT5HUbXWiKgxRlM1NbuGpICN9JIFuejxKmumBkEoFF/Jg+5XKZGAKKdiVG72kWwsY6D8T3WUcN8If9s2HacSBbsyeZ712OoOnh9vyyqu0TtQ5Z8BOPzO2tJImd05j4hZ3t/EO35vmeMdOM5BA6SS9TJ11E2cZuc2ARQlfIquW9yrQW+FmwFuVG6aqNXZA9c4YjQHn1xifuZ8HFZsSQpuG5KZQzOTUEivMtn7Ct7UK9MAlK7nQblxtpW5iYGpWxsrfh0GXp7+8olOY3dm8iHqwyoPoXEOVjnZPxOEn2dg9oJT3TOvcO85jwM3CkeyvPkzJeStqz2n1xFipETr7WRDekK0j7Z4qDmP6VZA0B3C4+91Occ0kKJDPtsHAUTMpkyhMTZEXCbFT1R8gfiOhFeWLzd4cOsTiUSpXSk9oG68kJ3uEaP0uXUH9eNVRXeHthGlxbl71AxkeOJa4nP8Fot5ZLaXYg8CWQ4NnC4YITBMdoBiiYKNwsPCJBiEueiuEB5puO/NS+ZOO346COxtalX8a1PKShFNw3bCvaHg54jIMsrPNy0K6mpas/h4u8iBgt8whk/AGDvTDjnyI8+rDfG+DROft2cDDJJx6cCxBOMtT2PDxx3Gb51eyjVhC5iWLTX3kUXfXrBUy+LlvZR43xCZHvAF5QEbTXbrCi5xoLoBim99k2mt56IoYYuBoPhQROzg/UIoohFGOrCKE6fz/VOlftElLDwgyNoLIdrHZv/H+FxYcE8L4UmZptMRa/QCiaNTL/j7jebBA2sgFu1GJeV5tfNP4qXfgmkzKFppb33adHdbF/wmQba4cS+Yxav4EE5pCCeIX0Bimrbfrp+ygUxgKtYZXiu9wmYDrgaHuFWxPjm+vZym1+SR9V3P0sv0zC8OE1rMzvMknBY7HLhyhf3zMItMMQDRabR/IfjMLCw8RjFKxWjgRGjVrT3R2Z9LdolbFV6usttvisLDWeEZiuIIPxQ2DHWfDQYf2mHY6cxnw3jCCBUEGCSqGSIb3DQEHAaCCBTIEggUuMIIFKjCCBSYGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAjpUIitGHGxFQICCAAEggTItZnpR7lMzolKkmZWdF4J8rKn7nkXXKOCicCxvt2sbRuMdH7mEH7S5uM7NAYHk0bXdHe7qGHVnfuM1HNiaEqLkOp2fRPMsHisSaakObIwmocVy7rLswNLkChV6feBpncAz8LJQDXdTy69N89olpzEJiV9AI8wRSZeiJmTQJ+d+ulGIYgT/JyPFOcA7XfHnt7wvBuG0rD/AlTfQy6HW26S6Ig+OXOKNh1QCs8IaQCyFVIv4A/jxWnRQTVnf/0+I9rBN8uOpME+7IhaAAYfz13POyix9ALrBfxEOdWDDYx1U+51/L7LbMg+nCjlzwCpbqd08VPqsKXLu7K8sZJbwMRxORsLsRvdaYK392d5GyDyLmi01gYtyfCWOB/nnzZb+XHKlryTO0nl0THqV8p3PQW61kvsoRCa8COY88Gbj0Y2LstQm7ClSxXI9F9D7RRkVsA/rzUKtOMgBIQP6MyZTo4e8vgrxn1Mg/yoz/JcN+DkX1vfPl2gIq4sBP50Yx+ceLKXrjSNNqCOoQ98egtioSoRP5G9yWIiyHqjZICg5t6ftVvUYoqkEcgg4rrE1UUNTQ5bL7w2Tg7J8V1H9apKyUSybdsxoVUlHO54BchhihPvXkB8qtCx4PSeNOZF1EiZT4z7IeKLr9Kj9AYFDaN/Gli6akBJENC3sl1+fQxXc3sPYfzkCWyrCzRd2tdxWAcdqgBBOXxkm2kzQtaDj7J7N5xoMHpeqltpXdv49L04rXsjin+FhB4FNWrf9xYNAXn2vjpjCUg2CcIO+PzoIFr5avsv99dq9LLYemw1P3CnKOe5TWsWWJdDTCXsviOFssiqv6l3OdjIirwxm96sX2Z1AayvLBpGCvn2JoJkOzSE9rO9g3ramuGOi1cjwHrIGNr/G3wZn9ft4wJXpBRUcxL/xK73ZpIRga2rSrG5Se3RELy898kCYnCNNa6zcfd5/eV8d1+5WMCMW9uRh7mpVbHVND1TVcruZeXToyjNb6q9UjRIhgWUlLWCCFMbX5Md41c/RqvTuN+CvcXMzOmrjfaQk81JK0csvT121CWJtd+QSkUSgyhAYzCj7MQMurtUKJx1EZ2fXFsVo0K0mjzcwU38wKqAZfn2hkTWcp5NyATO9nJ71z1PiBY/XAQsbv3eApf4WRQTwogq8XXpbx7Hm61TseJUfilTBlMlKj5CHmZrDFhBAIzIVixzydTwHGNsoqJ+/tnkaUWyAA2+C7kvMjtat5Mj/WavT/cYP7nmm/CTETCsXazmnQFXFI0egHPx88Icf9XgW27tBsgBMb4+KJRjvlnqjztNqzs5Eh52/dXupWmgS9q0Y8IcmHbFDjpfOXz9vB24/HhBe6U2kzn4WIHq6FbZZikjoHKX2V/I1QNDpZQj5ZI6w+pdoLHokHdz9K5PD3oZIf12Y/1RxzGVPNkCfvzO94eWmGaPmbE5mmRWEcYIbT5FvL0NZyAxztlHABxGbUDiOG/qNR1h7q1UiEhVv/CIZauij+8USbG7wFtuVxo5/enPdld9E32XSLCv+TjByfbxPiHkoCw8XkSbtyBq/0KtdiJ7CX2JtK74P5Jw/i/cshMdTX6V/r439g8YESV5XTCU7kLJMzI3iSBg6/5PoC+Ckho5xpcPSBmGMSUwIwYJKoZIhvcNAQkVMRYEFNPHWcwMABpZYlB+Bl74m8ceTJwmMDEwITAJBgUrDgMCGgUABBRIYzYkD++kAMXAxtTQ9+DDCK9LKAQIAK8dKmYIyIICAggA";
            byte[] data = Convert.FromBase64String(testPfx);
            File.WriteAllBytes(pfxName, data);
            AuthenticatedPFX aPfx = new AuthenticatedPFX(pfxName, pfxPwd, "", "");
            CertificateStorageManager certMgr = new CertificateStorageManager(aPfx, true);
            try {
                certMgr.ProcessPFX();
            } catch (Exception e) {
                Console.WriteLine(e);
                Assert.Fail();
            }
        }
    }
}