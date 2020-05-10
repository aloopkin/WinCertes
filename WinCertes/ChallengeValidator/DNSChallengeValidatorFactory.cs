using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinCertes.ChallengeValidator
{
    static class DNSChallengeValidatorFactory
    {
        /// <summary>
        /// Builds the DNS Challenge validator. For now only ACME DNS is supported.
        /// </summary>
        /// <returns>challengeValidator instance</returns>
        public static IDNSChallengeValidator GetDNSChallengeValidator()
        {
            string dnsValidatorType = Program._winCertesOptions.DNSValidatorType;

            IDNSChallengeValidator challengeValidator = null;
            if (dnsValidatorType == null || dnsValidatorType.Length < 1)
                return null;
            if (dnsValidatorType == "acme-dns") {
                challengeValidator = new DNSChallengeAcmeDnsValidator();
            }
            if (dnsValidatorType == "win-dns") {
                challengeValidator = new DNSChallengeWinDnsValidator();
            }
            return challengeValidator;
        }
    }
}
