using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace WinCertes.ChallengeValidator
{
    class DNSChallengeAcmeDnsValidator : IDNSChallengeValidator
    {
        private IConfig _config;

        /// <summary>
        /// Constructor for the ACME-DNS DNS challenge validator
        /// </summary>
        /// <param name="config"></param>
        public DNSChallengeAcmeDnsValidator(IConfig config)
        {
            _config = config;
        }

        /// <summary>
        /// Preparing ACME-DNS by sending ACME DNS token using ACME-DNS credentials and API.
        /// </summary>
        /// <param name="dnsKeyName"></param>
        /// <param name="dnsKeyValue"></param>
        /// <returns></returns>
        public bool PrepareChallengeForValidation(string dnsKeyName, string dnsKeyValue)
        {
            var DNSServerURL = _config.ReadStringParameter("DNSServerURL");
            var DNSServerUser = _config.ReadStringParameter("DNSServerUser");
            var DNSServerKey = _config.ReadStringParameter("DNSServerKey");
            var DNSServerSubDomain = _config.ReadStringParameter("DNSServerSubDomain");

            HttpClient client = new HttpClient();
            var content = new StringContent($"{{ \"subdomain\": \"{DNSServerSubDomain}\", \"txt\": \"{dnsKeyValue}\" }}", Encoding.UTF8, "application/json");
            content.Headers.Add("X-Api-User", DNSServerUser);
            content.Headers.Add("X-Api-Key", DNSServerKey);

            var response = client.PostAsync(DNSServerURL, content).Result;
            return (response.StatusCode == System.Net.HttpStatusCode.OK);
        }
    }
}
