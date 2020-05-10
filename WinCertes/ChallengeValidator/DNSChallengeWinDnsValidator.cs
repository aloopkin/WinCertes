using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;

namespace WinCertes.ChallengeValidator
{
    class DNSChallengeWinDnsValidator : IDNSChallengeValidator
    {
        private static readonly ILogger logger = LogManager.GetLogger("WinCertes.ChallengeValidator.DNSChallengeWinDnsValidator");
        private WinCertesOptions _options;
        private String DNSServerHost;
        private String DNSServerUser;
        private String DNSServerPassword;
        private String DNSServerZone;

        /// <summary>
        /// Constructor for the Windows-DNS DNS challenge validator
        /// </summary>
        /// <param name="config"></param>
        public DNSChallengeWinDnsValidator()
        {
            _options = Program._winCertesOptions;
            DNSServerHost = _options.DNSServerHost;
            DNSServerUser = _options.DNSServerUser;
            DNSServerPassword = _options.DNSServerPassword;
            DNSServerZone = _options.DNSServerZone;
        }

        /// <summary>
        /// Updates MS Windows DNS for ACME DNS Validation
        /// </summary>
        /// <param name="dnsKeyName"></param>
        /// <param name="dnsKeyValue"></param>
        /// <returns></returns>
        public bool PrepareChallengeForValidation(string dnsKeyName, string dnsKeyValue)
        {
            ManagementScope mgmtScope = new ManagementScope(@"\\" + DNSServerHost + @"\Root\MicrosoftDNS");
            if (DNSServerUser != null) mgmtScope.Options = LoginOptions();
            mgmtScope.Connect();

            ManagementObjectSearcher mgmtSearch = new ManagementObjectSearcher(mgmtScope, new ObjectQuery(string.Format("SELECT * FROM MicrosoftDNS_TXTType WHERE OwnerName = '{0}'", dnsKeyName)));
            ManagementObjectCollection mgmtDNSRecords = mgmtSearch.Get();

            if (mgmtDNSRecords.Count >= 1) {
                foreach (ManagementObject mgmtDNSRecord in mgmtDNSRecords) {
                    ManagementBaseObject mgmtParams = mgmtDNSRecord.GetMethodParameters("Modify");
                    mgmtParams["DescriptiveText"] = dnsKeyValue;
                    mgmtDNSRecord.InvokeMethod("Modify", mgmtParams, null);
                    break;
                }
                logger.Debug($"Updated DNS record of type [TXT] with name [{dnsKeyName}]");
                return true;
            } else if (mgmtDNSRecords.Count == 0) {
                ManagementClass mgmtClass = new ManagementClass(mgmtScope, new ManagementPath("MicrosoftDNS_TXTType"), null);
                ManagementBaseObject mgmtParams = mgmtClass.GetMethodParameters("CreateInstanceFromPropertyData");
                mgmtParams["DnsServerName"] = Environment.MachineName;
                if (DNSServerZone == null) DNSServerZone = dnsKeyName.Split('.')[dnsKeyName.Split('.').Count() - 2] + "." + dnsKeyName.Split('.')[dnsKeyName.Split('.').Count() - 1];
                mgmtParams["ContainerName"] = DNSServerZone;
                mgmtParams["OwnerName"] = dnsKeyName;
                mgmtParams["DescriptiveText"] = dnsKeyValue;
                mgmtClass.InvokeMethod("CreateInstanceFromPropertyData", mgmtParams, null);
                logger.Debug($"Created DNS record of type [TXT] with name [{dnsKeyName}]");
                return true;
            }
            return false;
        }

        private ConnectionOptions LoginOptions()
        {
            ConnectionOptions connOpt = new ConnectionOptions();
            connOpt.Username = DNSServerUser;
            connOpt.Password = DNSServerPassword;
            connOpt.Impersonation = ImpersonationLevel.Impersonate;
            return connOpt;
        }
    }
}
