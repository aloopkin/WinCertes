using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinCertes.ChallengeValidator
{
    class DNSChallengeValidatorFactory
    {
        /// <summary>
        /// Builds the DNS Challenge validator. For now only ACME DNS is supported.
        /// </summary>
        /// <param name="config"></param>
        /// <returns></returns>
        public static IDNSChallengeValidator GetDNSChallengeValidator(IConfig config)
        {
            IDNSChallengeValidator challengeValidator = null;
            if (config.ReadStringParameter("DNSValidatorType") == null) return null;
            if (config.ReadStringParameter("DNSValidatorType") == "acme-dns") {
                challengeValidator = new DNSChallengeAcmeDnsValidator(config);
            }
            if (config.ReadStringParameter("DNSValidatorType") == "win-dns") {
                challengeValidator = new DNSChallengeWinDnsValidator(config);
            }
            return challengeValidator;
        }
    }
}
