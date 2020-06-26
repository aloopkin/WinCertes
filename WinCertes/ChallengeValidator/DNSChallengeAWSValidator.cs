using Amazon.Route53;
using Amazon.Route53.Model;
using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinCertes.ChallengeValidator
{
    class DNSChallengeAWSValidator : IDNSChallengeValidator
    {
        private static readonly ILogger logger = LogManager.GetLogger("WinCertes.ChallengeValidator.DNSChallengeAWSValidator");
        private IConfig _config;
        private string zoneId = null;
        private AmazonRoute53Client route53Client;

        /// <summary>
        /// Constructor for the ACME-DNS DNS challenge validator
        /// </summary>
        /// <param name="config"></param>
        public DNSChallengeAWSValidator(IConfig config)
        {
            _config = config;
            zoneId = _config.ReadStringParameter("DNSAWSZoneId");
        }

        public bool PrepareChallengeForValidation(string dnsKeyName, string dnsKeyValue)
        {
            try
            {
                route53Client = new AmazonRoute53Client();
                HostedZone zone = null;
                if (zoneId != null)
                {
                    GetHostedZoneResponse zoneResp = route53Client.GetHostedZone(new Amazon.Route53.Model.GetHostedZoneRequest { Id = zoneId });
                    zone = zoneResp.HostedZone;
                }
                else
                {
                    ListHostedZonesResponse zones = route53Client.ListHostedZones();
                    string recordToZone = dnsKeyName;
                    while (recordToZone.IndexOf('.') > 0)
                    {
                        recordToZone = recordToZone.Substring(recordToZone.IndexOf('.') + 1);
                        zone = zones.HostedZones.Where(z => z.Name.Contains(recordToZone)).FirstOrDefault();
                        if (zone != null)
                            break;
                    }
                }
                if (zone == null)
                {
                    logger.Error("Could not find DNS zone");
                    return false;
                }

                ListResourceRecordSetsResponse txtRecordsResponse = route53Client.ListResourceRecordSets(new ListResourceRecordSetsRequest
                {
                    StartRecordName = dnsKeyName,
                    StartRecordType = "TXT",
                    MaxItems = "1",
                    HostedZoneId = zone.Id
                });
                ResourceRecordSet txtRecord = txtRecordsResponse.ResourceRecordSets.FirstOrDefault(r => (r.Name == dnsKeyName || r.Name == dnsKeyName + ".") && r.Type.Value == "TXT");

                if (txtRecord != null)
                {
                    ApplyDnsChange(zone, txtRecord, ChangeAction.DELETE);

                }

                txtRecord = new ResourceRecordSet()
                {
                    Name = dnsKeyName,
                    TTL = 5,
                    Type = RRType.TXT,
                    ResourceRecords = new List<ResourceRecord>
                {
                    new ResourceRecord { Value = "\""+dnsKeyValue+"\"" }
                }
                };

                ApplyDnsChange(zone, txtRecord, ChangeAction.UPSERT);
            }
            catch (AmazonRoute53Exception exp)
            {
                logger.Error($"Could not update AWS Route53 record: ", exp);
                return false;
            }
            return true;
        }

        private bool ApplyDnsChange(HostedZone zone, ResourceRecordSet recordSet, ChangeAction action)
        {
            // Prepare change as Batch
            Change changeDetails = new Change()
            {
                ResourceRecordSet = recordSet,
                Action = action
            };

            ChangeBatch changeBatch = new ChangeBatch()
            {
                Changes = new List<Change> { changeDetails }
            };

            // Prepare zone's resource record sets
            var recordsetRequest = new ChangeResourceRecordSetsRequest()
            {
                HostedZoneId = zone.Id,
                ChangeBatch = changeBatch
            };

            logger.Debug($"Route53 :: ApplyDnsChange : ChangeResourceRecordSets: {recordsetRequest.ChangeBatch} ");

            var recordsetResponse = route53Client.ChangeResourceRecordSets(recordsetRequest);

            logger.Debug($"Route53 :: ApplyDnsChange : ChangeResourceRecordSets Response: {recordsetResponse} ");

            logger.Info("DNS change completed.");

            return true;
        }

    }
}
