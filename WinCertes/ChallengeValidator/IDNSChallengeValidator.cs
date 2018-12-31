using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinCertes.ChallengeValidator
{
    /// <summary>
    /// Interface fopr DNS Challenge Validation
    /// </summary>
    public interface IDNSChallengeValidator
    {
        /// <summary>
        /// Prepare DNS System for Challenge Validation
        /// </summary>
        /// <param name="dnsKeyName">The DNS Key Name (in the form _acme-challenge.example.com)</param>
        /// <param name="dnsKeyValue">The DNS Key Value (TXT value of the former)</param>
        /// <returns></returns>
        bool PrepareChallengeForValidation(string dnsKeyName, string dnsKeyValue);
    }
}
