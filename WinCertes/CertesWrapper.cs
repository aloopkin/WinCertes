using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using NLog;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using WinCertes.ChallengeValidator;

namespace WinCertes
{
    /// <summary>
    /// Commodity class to store Certes settings
    /// </summary>
    public class CertesSettings
    {
    }

    /// <summary>
    /// CertesWrapper class: a wrapper around Certes library, that simplifies handling ACME requests in the context of WinCertes
    /// </summary>
    /// <seealso cref="Certes"/>
    internal class CertesWrapper
    {
        private static readonly ILogger logger = Program._logger; // LogManager.GetLogger("WinCertes.CertesWrapper");
        private AcmeContext _acme;
        private IOrderContext _orderCtx = null;
        private HttpClient _httpClient = null;
        private WinCertesOptions _options;

        /// <summary>
        /// Initializes Certes library context using ServiceUri, AccountKey
        /// </summary>
        private void InitCertes()
        {
            _acme = new AcmeContext(_options.ServiceUri, KeyFactory.FromPem(_options.AccountKey), new AcmeHttpClient(_options.ServiceUri, _httpClient));
        }

        /// <summary>
        /// CertesWrapper class constructor
        /// </summary>
        /// <param name="serviceUri">The ACME service URI (endin in /directory). If null, defaults to Let's encrypt</param>
        /// <param name="accountEmail">The email address to be registered within the ACME account. If null, no email will be used</param>
        internal CertesWrapper()
        {
            _options = Program._winCertesOptions;

            logger.Debug($"Uri: {_options.ServiceUri.ToString()}");
            // Todo - Encrypt this in registry
            //logger.Debug($"PFX password will be: {_options.PfxPassword}");

            // Basic check of private key
            string key = _options.AccountKey;
            if ( key == null || key.Length < 1500 )
            {
                // Create new private key
                _options.AccountKey = KeyFactory.NewKey(KeyAlgorithm.RS256).ToPem();
            }

            // Instantiating HTTP Client
            AssemblyName certesAssembly = typeof(AcmeContext).Assembly.GetName();
            AssemblyName winCertesAssembly = typeof(Program).Assembly.GetName();
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", $"WinCertes/{winCertesAssembly.Version.ToString()} (Certes/{certesAssembly.Version.ToString()}; {Environment.OSVersion.VersionString})");
        }

        /// <summary>
        /// Fetches the useful error messages from within the exceptions stack within Certes
        /// </summary>
        /// <param name="exp">the exception to process</param>
        /// <returns>the error messages concatenated as string</returns>
        private string ProcessCertesException(Exception exp)
        {
            string errorMessage = exp.Message;
            if (exp.InnerException != null) {
                errorMessage += " - " + exp.InnerException.Message;
                if (exp.InnerException.InnerException != null) errorMessage += " - " + exp.InnerException.InnerException.Message;
            }
            return errorMessage;
        }

        /// <summary>
        /// Register the local computer's account on the ACME service
        /// </summary>
        /// <returns>true if registration is successful, false otherwise</returns>
        public async Task<bool> RegisterNewAccount()
        {
            WinCertesOptions _options = Program._winCertesOptions;

            try {
                InitCertes();
                Certes.Acme.Resource.Directory directory = await _acme.GetDirectory();
                InitCertes();
                IAccountContext accountCtx = await _acme.NewAccount(_options.AccountEmail, true);
                _options.Registered = true;
                logger.Info($"Successfully registered account {_options.AccountEmail} with certificate authority {_options.ServiceUri.ToString()}");
                if ((directory.Meta != null) && (directory.Meta.TermsOfService != null))
                {
                    logger.Info($"Please check the ACME Service ToS at: {directory.Meta.TermsOfService.ToString()}");
                }
                return true;
            }
            catch (Exception exp)
            {
                logger.Error($"Failed to register account {_options.AccountEmail} with certificate authority {_options.ServiceUri.ToString()}: {ProcessCertesException(exp)}");
                return false;
            }
        }

        /// <summary>
        /// Register a new order on the ACME service, for the specified domains. Challenges will be automatically verified.
        /// This method manages automatically the creation of necessary directory and files.
        /// </summary>
        /// <remarks>
        /// When using HTTP Validation, the ACME directory will access to http://__domain__/.well-known/acme-challenge/token, that should be served 
        /// by a local web server when not using built-in, and translated into local path {challengeVerifyPath}\.well-known\acme-challenge\token.
        /// Important Note: currently WinCertes supports only http-01 validation mode, and dns-01 validation mode with limitations.
        /// </remarks>
        /// <param name="domains">The list of domains to be registered and validated</param>
        /// <param name="httpChallengeValidator">The object used for challenge validation</param>
        /// <returns>True if successful</returns>
        public async Task<bool> RegisterNewOrderAndVerify(IList<string> domains, IHTTPChallengeValidator httpChallengeValidator, IDNSChallengeValidator dnsChallengeValidator)
        {
            try {
                // Re-init to be sure to get a fresh Nonce
                InitCertes();

                // Creating the order
                _orderCtx = await _acme.NewOrder(domains);
                if (_orderCtx == null) throw new Exception("Could not create certificate order.");

                // And fetching authorizations
                var orderAuthz = await _orderCtx.Authorizations();

                // Looping through authorizations
                foreach (IAuthorizationContext authz in orderAuthz) {
                    InitCertes();
                    await ValidateAuthz(authz, httpChallengeValidator, dnsChallengeValidator);
                }
                _options.CertificateChallenged = true;
                // If we are here, it means order was properly created, and authorizations & challenges were properly verified.
                logger.Info($"Generated orders and validated challenges for domains: {String.Join(",", domains)}");
                return true;
            } catch (Exception exp) {
                logger.Debug(exp, "Error while trying to register and validate order");
                logger.Error($"Failed to register and validate order with CA: {ProcessCertesException(exp)}");
                _options.CertificateChallenged = false;
                return false;
            }
        }

        /// <summary>
        /// Validates an Authorization, switching between DNS and HTTP challenges
        /// </summary>
        /// <param name="authz"></param>
        /// <param name="httpChallengeValidator"></param>
        /// <returns></returns>
        private async Task ValidateAuthz(IAuthorizationContext authz,IHTTPChallengeValidator httpChallengeValidator, IDNSChallengeValidator dnsChallengeValidator)
        {
            // For each authorization, get the challenges
            var allChallenges = await authz.Challenges();
            var res = await authz.Resource();
            if (dnsChallengeValidator != null) {
                // Get the DNS challenge
                var dnsChallenge = await authz.Dns();
                if (dnsChallenge != null) {
                    logger.Debug($"Initiating DNS Validation for {res.Identifier.Value}");
                    var resValidation = await ValidateDNSChallenge(res.Identifier.Value, dnsChallenge, dnsChallengeValidator);
                    if (!resValidation) throw new Exception($"Could not validate DNS challenge:\n {dnsChallenge.Resource().Result.Error.Detail}");
                } else throw new Exception("DNS Challenge Validation set up, but server sent no DNS Challenge");
            } else {
                // Get the HTTP challenge
                var httpChallenge = await authz.Http();
                if (httpChallenge != null) {
                    logger.Debug($"Initiating HTTP Validation for {res.Identifier.Value}");
                    var resValidation = await ValidateHTTPChallenge(httpChallenge, httpChallengeValidator);
                    if (!resValidation) throw new Exception($"Could not validate HTTP challenge:\n {httpChallenge.Resource().Result.Error.Detail}");
                } else throw new Exception("HTTP Challenge Validation set up, but server sent no HTTP Challenge");
            }
        }

        /// <summary>
        /// Validates a DNS challenge. Similar to HTTP Validation, but different because of DNSChallenge value which is signed by account key
        /// </summary>
        /// <param name="dnsChallenge"></param>
        /// <returns></returns>
        private async Task<bool> ValidateDNSChallenge(String domain, IChallengeContext dnsChallenge, IDNSChallengeValidator dnsChallengeValidator)
        {
            if (dnsChallenge == null) throw new Exception("DNS Validation mode setup, but server returned no DNS challenge.");
            // We get the resource fresh
            var dnsChallengeStatus = await dnsChallenge.Resource();

            // If it's invalid, we stop right away. Should not happen, but anyway...
            if (dnsChallengeStatus.Status == ChallengeStatus.Invalid) throw new Exception("DNS challenge has an invalid status");

            // Let's prepare for ACME-DNS validation
            var dnsValue = _acme.AccountKey.DnsTxt(dnsChallenge.Token);
            var dnsKey = $"_acme-challenge.{domain}".Replace("*.", "");
            if (!dnsChallengeValidator.PrepareChallengeForValidation(dnsKey, dnsValue)) return false;

            // Now let's ping the ACME service to validate the challenge token
            Challenge challengeRes = await dnsChallenge.Validate();

            // We need to loop, because ACME service might need some time to validate the challenge token
            int retry = 0;
            while (((challengeRes.Status == ChallengeStatus.Pending) || (challengeRes.Status == ChallengeStatus.Processing)) && (retry < 10)) {
                // We sleep 2 seconds between each request, to leave time to ACME service to refresh
                System.Threading.Thread.Sleep(2000);
                // We refresh the challenge object from ACME service
                challengeRes = await dnsChallenge.Resource();
                retry++;
            }

            // If challenge is Invalid, Pending or Processing, something went wrong...
            if (challengeRes.Status != ChallengeStatus.Valid) return false;

            return true;
        }


        /// <summary>
        /// Small method that validates one challenge using the specified validator
        /// </summary>
        /// <param name="httpChallenge"></param>
        /// <param name="challengeValidator"></param>
        /// <returns>true if validated, false otherwise</returns>
        private async Task<bool> ValidateHTTPChallenge(IChallengeContext httpChallenge, IHTTPChallengeValidator challengeValidator)
        {
            // We get the resource fresh
            var httpChallengeStatus = await httpChallenge.Resource();

            // If it's invalid, we stop right away. Should not happen, but anyway...
            if (httpChallengeStatus.Status == ChallengeStatus.Invalid) throw new Exception("HTTP challenge has an invalid status");

            // Else we start the challenge validation
            if (!challengeValidator.PrepareChallengeForValidation(httpChallenge.Token, httpChallenge.KeyAuthz)) return false;

            // Now let's ping the ACME service to validate the challenge token
            Challenge challengeRes = await httpChallenge.Validate();

            // We need to loop, because ACME service might need some time to validate the challenge token
            int retry = 0;
            while (((challengeRes.Status == ChallengeStatus.Pending) || (challengeRes.Status == ChallengeStatus.Processing)) && (retry < 10)) {
                // We sleep 2 seconds between each request, to leave time to ACME service to refresh
                System.Threading.Thread.Sleep(2000);
                // We refresh the challenge object from ACME service
                challengeRes = await httpChallenge.Resource();
                retry++;
            }

            // Finally we cleanup everything that was needed for validation
            challengeValidator.CleanupChallengeAfterValidation(httpChallenge.Token);
            // If challenge is Invalid, Pending or Processing, something went wrong...
            if (challengeRes.Status != ChallengeStatus.Valid) return false;

            return true;
        }

        /// <summary>
        /// Retrieves the CA chain from local computer's Root store, as a PEM chain
        /// </summary>
        /// <returns>PEM chain of local computer's CA certificates</returns>
        public byte[] GetCACertChainFromStore()
        {
            string pemBundle = "";

            pemBundle += DumpStoreContentsAsPEMBundle(StoreName.Root);
            pemBundle += DumpStoreContentsAsPEMBundle(StoreName.CertificateAuthority);

            return Encoding.UTF8.GetBytes(pemBundle);
        }

        /// <summary>
        /// Dumps the contents of a windows certificate store as a PEM bundle
        /// </summary>
        /// <param name="name">the store name</param>
        /// <returns>the PEM bundle, as a string</returns>
        private string DumpStoreContentsAsPEMBundle(StoreName name)
        {
            X509Store store = new X509Store(name, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var chain = "";
            X509Certificate2Collection certsW = store.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.KeyCertSign, true);

            foreach (X509Certificate2 certW in certsW) {
                StringBuilder builder = new StringBuilder();
                builder.AppendLine("-----BEGIN CERTIFICATE-----");
                builder.AppendLine(Convert.ToBase64String(certW.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END CERTIFICATE-----");
                chain += builder.ToString();
            }
            store.Close();

            return chain;
        }

        /// <summary>
        /// Retrieves the certificate from the ACME service. This method also generates the key and the CSR.
        /// </summary>
        /// <param name="domains">Full Domain list</param>
        /// <param name="fullPathForPfx">The full file path where the resulting PFX/PKCS#12 file will be generated</param>
        /// <param name="pfxFriendlyName">Friendly name for the resulting PFX/PKCS#12</param>
        /// <param name="writePEM">Export all certificates</param>
        /// <returns>The name of the generated PFX/PKCS#12 file, or null in case of error</returns>
        public async Task<string> RetrieveCertificate(IList<string> domains, string fullPathForPfx, string pfxFriendlyName, bool writePEM = false)
        {
            try {
                string pathForPfx = Path.GetDirectoryName(fullPathForPfx);
                if (_orderCtx == null) throw new Exception("Do not call RetrieveCertificate before RegisterNewOrderAndVerify");
                if (!System.IO.Directory.Exists(pathForPfx)) throw new Exception("Directory for PFX writing do not exists");

                InitCertes();

                // Let's generate a new key (RSA is good enough IMHO)
                IKey certKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
                // Then let's generate the CSR
                var csr = await _orderCtx.CreateCsr(certKey);
                csr.AddName("CN", domains[0]);
                csr.SubjectAlternativeNames = domains;

                // and finalize the ACME order
                var finalOrder = await _orderCtx.Finalize(csr.Generate());
                // Now we can fetch the certificate
                CertificateChain certChain = await _orderCtx.Download();
                _options.CertificateGenerated = true;
                // .cer: Full Certificate with Private Key. e.g. Visual SVN
                string cer = certChain.ToPem(certKey);
                // .pem: Full Certificate without Private Key e.g. hMailServer
                string pem = certChain.ToPem();
                // .pkey: Private key in separate PEM file.
                string pkey = certKey.ToPem();

                var fileName = Path.GetFileNameWithoutExtension(fullPathForPfx);
                string pfxName = fileName + ".pfx";
                string pfxPath = pathForPfx + "\\" + pfxName;
                string cerPath = pathForPfx + "\\" + fileName + ".cer";
                string pemPath = pathForPfx + "\\" + fileName + ".pem";
                string pkeyPath = pathForPfx + "\\" + fileName + ".pkey";

                // We build the PFX/PKCS#12
                var pfx = certChain.ToPfx(certKey);
                pfx.AddIssuers(GetCACertChainFromStore());
                var pfxBytes = pfx.Build(pfxFriendlyName, _options.PfxPassword);

                // We write the PFX/PKCS#12 to file
                System.IO.File.WriteAllBytes(fullPathForPfx, pfxBytes);
                logger.Info($"Output complete certificate PFX. The certificate is in {fullPathForPfx}");

                if (writePEM)
                {
                    System.IO.File.WriteAllText(cerPath, cer);
                    logger.Info($"Output complete certificate PEM. The certificate is in {cerPath}");

                    System.IO.File.WriteAllText(pemPath, pem);
                    logger.Info($"Output public certificate PEM. The certificate is in {pemPath}");

                    System.IO.File.WriteAllText(pkeyPath, pkey);
                    logger.Info($"Output Private certificate PEM. The certificate is in {pkeyPath}");
                }
                return pfxName;
            } catch (Exception exp) {
                logger.Error($"Failed to retrieve certificate from CA: {ProcessCertesException(exp)}");
                _options.CertificateGenerated = false;
                return null;
            }
        }

        /// <summary>
        /// Revokes the provided certificate from the ACME Service.
        /// </summary>
        /// <param name="certificate">the certificate to revoke</param>
        /// <returns>true in case of success, false otherwise</returns>
        public async Task<bool> RevokeCertificate(X509Certificate2 certificate, int reason)
        {
            if (certificate == null) return false;
            try {
                InitCertes();

                RevocationReason rr = (RevocationReason)(Enum.GetValues(RevocationReason.Unspecified.GetType())).GetValue(reason);
                await _acme.RevokeCertificate(certificate.RawData, rr, null);

                return true;
            } catch (Exception exp) {
                logger.Error($"Failed to revoke certificate with serial {certificate.GetSerialNumberString()} from CA: {ProcessCertesException(exp)}");
                return false;
            }
        }
    }
}
