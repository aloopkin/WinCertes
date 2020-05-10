using Mono.Options;
using NLog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using WinCertes.ChallengeValidator;

namespace WinCertes
{
    /// <summary>
    /// WinCertes2 LetsEncrypt
    /// </summary>
    /// <remarks>
    /// Sample command line for debugging this application:
    /// wincertes.exe
    /// wincertes.exe --debug -a -x -e wincertes@mydomain.com -d wincertes.mydomain.com -d mail.mydomain.com  -s https://acme-staging-v02.api.letsencrypt.org/directory
    /// wincertes.exe --debug -a -x -e wincertes@mydomain.com -n wincertes.mydomain.com -d wincertes.mydomain.com  -s https://acme-staging-v02.api.letsencrypt.org/directory
    /// wincertes.exe --debug -a -x -e wincertes@mydomain.com -n wincertes.mydomain.com -d wincertes.mydomain.com -d mail.mydomain.com  -s https://acme-staging-v02.api.letsencrypt.org/directory
    /// wincertes.exe --debug -a -x -e wincertes@mydomain.com -n wincertes.mydomain.com -d mail.mydomain.com  -s https://acme-staging-v02.api.letsencrypt.org/directory
    /// wincertes.exe --debug -a -x -n wincertes.mydomain.com -d mail.mydomain.com  -s https://acme-staging-v02.api.letsencrypt.org/directory
    /// wincertes.exe --dnscreatekeys -n wincertes.mydomain.com
    /// wincertes.exe --debug --reset -n wincertes.mydomain.com
    /// wincertes.exe --debug --show -n wincertes.mydomain.com
    /// + genuine domain names
    /// </remarks>
    internal partial class Program
    {
        internal static readonly ILogger _logger = LogManager.GetLogger("WinCertes");
        internal static CertesWrapper _certesWrapper;
        internal static string _winCertesPath = Environment.CurrentDirectory + "\\Certificates";
        internal static string _logPath = Environment.CurrentDirectory + "\\Logs";

        /// <summary>
        /// Exit wrapper to pause command interface for debugging
        /// </summary>
        /// <param name="exitCode">The exit error code</param>
        /// <returns>The exit error code</returns>
        private static int MainExit(int exitCode)
        {
            if (exitCode != SUCCESS)
            {
                _logger.Error("Exit Code({0})", exitCode);
            }
            return exitCode;
        }

        /// <summary>
        /// Main programme
        /// </summary>
        /// <param name="args">WinCertes command line arguments</param>
        /// <returns>Zero if successul, error code otherwise</returns>
        private static int Main(string[] args)
        {
            // WinCertes Certificate path...
            InitWinCertesDirectoryPath(_winCertesPath);
            Utils.ConfigureLogger(_logPath, args);

            if (!Utils.IsAdministrator()) 
            {
                string message = "WinCertes.exe must be launched as Administrator with elevated permissions";
                _logger.Error(message);
                Thread.Sleep(1000);
                Utils.AdminRelauncher();
            }
            // Merge command line parameters with registry defaults
            int result = HandleOptions(args);
            if (result != 0 )
                return MainExit(result);

            // Display settings, don't create or renew the certificate
            if (_show)
            {
                _winCertesOptions.DisplayOptions(); 
                return MainExit(SUCCESS);
            }

            // Helper to create the DNS keys
            if (_creatednskeys)
            {
                _winCertesOptions.WriteDnsOptions();
                return MainExit(SUCCESS);
            }

            // Reset is a full reset!
            if (_reset)
            {
                Console.WriteLine("\nWARNING: You should revoke the certificate before deleting it from the registry\nDelete [{0}]?\nPress Enter when ready...", _winCertesOptions.Registry.FullRegistryKey);
                Console.ReadLine();
                _winCertesOptions.Registry.DeleteAllParameters();
                Utils.DeleteScheduledTasks();
                return MainExit(SUCCESS);
            }


            _logger.Info("Initialisation successful, processing your request...");
            string taskName = null;
            if (_periodic) taskName = Utils.DomainsToFriendlyName(_winCertesOptions.Domains);

            // Initialization and renewal/revocation handling
            try
            {
                InitCertesWrapper(_winCertesOptions);
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
                return MainExit(ERROR);
            }
            if (_winCertesOptions.Revoke > -1)
            { 
                RevokeCert(_winCertesOptions.Domains, _winCertesOptions.Revoke); 
                return MainExit(SUCCESS); 
            }
            // default mode: enrollment/renewal. check if there's something to be done
            // note that in any case, we want to be able to set the scheduled task (won't do anything if taskName is null)
            if (!IsThereCertificateAndIsItToBeRenewed(_winCertesOptions.Domains)) 
            { 
                Utils.CreateScheduledTask(taskName, _winCertesOptions.Domains, _extra); 
                return MainExit(SUCCESS); 
            }

            // Now the real stuff: we register the order for the domains, and have them validated by the ACME service
            IHTTPChallengeValidator httpChallengeValidator = HTTPChallengeValidatorFactory.GetHTTPChallengeValidator(_winCertesOptions.Standalone, _winCertesOptions.HttpPort, _winCertesOptions.WebRoot);
            IDNSChallengeValidator dnsChallengeValidator = DNSChallengeValidatorFactory.GetDNSChallengeValidator();
            if ((httpChallengeValidator == null) && (dnsChallengeValidator == null))
            {
                WriteErrorMessageWithUsage(_options, "Specify either an HTTP or a DNS validation method."); 
                return MainExit(ERROR_MISSING_HTTP_DNS);
            }
            if (!(Task.Run(() => _certesWrapper.RegisterNewOrderAndVerify(_winCertesOptions.Domains, httpChallengeValidator, dnsChallengeValidator)).GetAwaiter().GetResult()))
            {
                if (httpChallengeValidator != null) httpChallengeValidator.EndAllChallengeValidations();
                return MainExit(ERROR);
            }
            if (httpChallengeValidator != null) httpChallengeValidator.EndAllChallengeValidations();

            // We get the certificate from the ACME service
            string pfxFullFileName = _winCertesPath + "\\" + _winCertesOptions.CertificateName;
            var pfxName = Task.Run(() => 
                    _certesWrapper.RetrieveCertificate(_winCertesOptions.Domains, pfxFullFileName, Utils.DomainsToFriendlyName(_winCertesOptions.Domains), _winCertesOptions.ExportPem)
                ).GetAwaiter().GetResult();

            if (pfxName == null)
                return MainExit(ERROR);

            _logger.Info("Certificate file creation complete. Generate authenticated PFX");
            AuthenticatedPFX pfx = new AuthenticatedPFX(pfxFullFileName, _winCertesOptions.PfxPassword);
            CertificateStorageManager certificateStorageManager = new CertificateStorageManager(pfx, (_winCertesOptions.Csp == null) && (!_winCertesOptions.noCsp));

            // Let's process the PFX into Windows Certificate object.
            certificateStorageManager.ProcessPFX();

            // and we write its information to the WinCertes configuration
            RegisterCertificateIntoConfiguration(certificateStorageManager.Certificate, _winCertesOptions.Domains);

            // Import the certificate into the Windows store
            if (!_winCertesOptions.noCsp) certificateStorageManager.ImportCertificateIntoCSP(_winCertesOptions.Csp);

            // Bind certificate to IIS Site (won't do anything if option is null)
            Utils.BindCertificateForIISSite(certificateStorageManager.Certificate, _winCertesOptions.BindName);
            // Execute PowerShell Script (won't do anything if option is null)
            Utils.ExecutePowerShell(_winCertesOptions.ScriptFile, pfx);
            // Create the AT task that will execute WinCertes periodically (won't do anything if taskName is null)
            Utils.CreateScheduledTask(taskName, _winCertesOptions.Domains, _extra);

            // Let's delete the PFX file, if export was not enabled
            if (!_winCertesOptions.ExportPem)
            {
                RemoveFileAndLog(pfx.PfxFullPath);
            }

            return MainExit(SUCCESS);
        }

        /// <summary>
        /// Checks whether the enrolled certificate should be renewed
        /// </summary>
        /// <param name="config">WinCertes config</param>
        /// <returns>true if certificate must be renewed or does not exists, false otherwise</returns>
        private static bool IsThereCertificateAndIsItToBeRenewed(List<string> domains)
        {
            string certificateExpirationDate = _winCertesOptions.Registry.ReadStringParameter("certExpDate" + Utils.DomainsToHostId(domains));
            if ((certificateExpirationDate == null) || (certificateExpirationDate.Length == 0))
            {
                    _logger.Debug($"The certificate has not been registered");
                    return true;
            }
            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
            DateTime expirationDate = DateTime.Parse(certificateExpirationDate);
            DateTime futureThresold = DateTime.Now.AddDays(_winCertesOptions.Registry.ReadIntParameter("renewalDays", 30));
            if (futureThresold > expirationDate)
            {
                _logger.Debug($"Current certificate needs renewing, it expires: {certificateExpirationDate}");
                return true;
            }
            _logger.Debug($"Certificate exists, renewal is due before: {certificateExpirationDate}");
            return false;
        }

        /// <summary>
        /// Revoke certificate issued for specified list of domains
        /// </summary>
        /// <param name="domains"></param>
        private static void RevokeCert(List<string> domains, int revoke)
        {
            string serial = _winCertesOptions.Registry.ReadStringParameter("CertSerial" + Utils.DomainsToHostId(domains));
            if (serial == null)
            {
                _logger.Error($"Could not find certificate matching primary domain {domains[0]}. Please check the Subject CN of the certificate you wish to revoke");
                return;
            }
            X509Certificate2 cert = Utils.GetCertificateBySerial(serial);
            if (cert == null)
            {
                _logger.Error($"Could not find certificate matching serial {serial}. Please check the Certificate Store");
                return;
            }
            // Here we revoke from ACME Service. Note that any error is already handled into the wrapper
            if (Task.Run(() => _certesWrapper.RevokeCertificate(cert, revoke)).GetAwaiter().GetResult())
            {
                _winCertesOptions.Registry.DeleteParameter("CertExpDate" + Utils.DomainsToHostId(domains));
                _winCertesOptions.Registry.DeleteParameter("CertSerial" + Utils.DomainsToHostId(domains));
                X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                store.Remove(cert);
                store.Close();
                _logger.Info($"Certificate with serial {serial} for domains {String.Join(",", domains)} has been successfully revoked");
            }
        }

        /// <summary>
        /// Initializes WinCertes Directory path on the filesystem. The certificate may be overridden through registry.
        /// </summary>
        /// <param name="path">Preferred path for certificate files. Default is %PROGRAMDATA%\WinCertes</param>
        private static string InitWinCertesDirectoryPath(string path = null)
        {
            if (path == null)
                path = Program._winCertesOptions.CertificatePath;
            else
            if (!System.IO.Directory.Exists(path))
            {
                System.IO.Directory.CreateDirectory(path);
            }
            return path;
        }

        /// <summary>
        /// Registers certificate into configuration
        /// </summary>
        /// <param name="pfx"></param>
        /// <param name="domains"></param>
        private static void RegisterCertificateIntoConfiguration(X509Certificate2 certificate, List<string> domains)
        {
            // and we write its expiration date to the WinCertes configuration, into "InvariantCulture" date format
            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
            _winCertesOptions.Registry.WriteStringParameter("CertExpDate" + Utils.DomainsToHostId(domains), certificate.GetExpirationDateString());
            _winCertesOptions.Registry.WriteStringParameter("CertSerial" + Utils.DomainsToHostId(domains), certificate.GetSerialNumberString());
            _winCertesOptions.WriteOptionsIntoConfiguration();
        }

        /// <summary>
        /// Initializes the CertesWrapper, and registers the account if necessary
        /// </summary>
        /// <param name="serviceUri">the ACME service URI</param>
        /// <param name="email">the email account used to register</param>
        private static void InitCertesWrapper(WinCertesOptions _winCertesOptions)
        {
            // We get the CertesWrapper object, that will do most of the job.
            _certesWrapper = new CertesWrapper();

            // If local computer's account isn't registered on the ACME service, we'll do it.
            if (!_winCertesOptions.Registered)
            {
                var regRes = Task.Run(() => _certesWrapper.RegisterNewAccount()).GetAwaiter().GetResult();
                if (!regRes)
                    throw new Exception("Could not register ACME service account");
            }
        }

        /// <summary>
        /// Removes specified files and logs it
        /// </summary>
        /// <param name="path"></param>
        private static void RemoveFileAndLog(string path)
        {
            try
            {
                File.Delete(path);
                _logger.Info($"Removed file from filesystem: {path}");
            }
            catch (Exception e)
            {
                _logger.Error(e.Message);
            }
        }

    }
}