using Mono.Options;
using NLog;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Globalization;
using System.Threading;
using WinCertes.ChallengeValidator;
using System.IO;

namespace WinCertes
{
    class WinCertesOptions
    {
        public WinCertesOptions()
        {
            ServiceUri = null;
            Email = null;
            WebRoot = null;
            BindName = null;
            ScriptFile = null;
            Standalone = false;
            Revoke = false;
            Csp = null;
        }
        public string ServiceUri { get; set; }
        public string Email { get; set; }
        public string WebRoot { get; set; }
        public string BindName { get; set; }
        public string ScriptFile { get; set; }
        public bool Standalone { get; set; }
        public bool Revoke { get; set; }
        public string Csp { get; set; }

        public void WriteOptionsIntoConfiguration(IConfig config)
        {
            // write service URI into conf, or reads from it, if any
            ServiceUri = config.WriteAndReadStringParameter("serviceUri", ServiceUri);
            // write account email into conf, or reads from it, if any
            Email = config.WriteAndReadStringParameter("accountEmail", Email);
            // Should we work with the built-in web server
            Standalone = config.WriteAndReadBooleanParameter("standalone", Standalone);
            // do we have a webroot parameter to handle?
            WebRoot = config.WriteAndReadStringParameter("webRoot", WebRoot);
            // if not, let's use the default web root of IIS
            if ((WebRoot == null) && (!Standalone))
            {
                WebRoot = "c:\\inetpub\\wwwroot";
                config.WriteStringParameter("webRoot", WebRoot);
            }
            // Should we bind to IIS? If yes, let's do some config
            BindName = config.WriteAndReadStringParameter("bindName", BindName);
            // Should we execute some PowerShell ? If yes, let's do some config
            ScriptFile = config.WriteAndReadStringParameter("scriptFile", ScriptFile);
        }
    }

    class Program
    {
        private static readonly ILogger _logger = LogManager.GetLogger("WinCertes");

        private static CertesWrapper _certesWrapper;
        private static IConfig _config;
        private static string _winCertesPath;

        private static readonly string _additionalInfo = "\n*: these paremeters are not stored into configuration.\n\n"
            + "Typical usage: WinCertes.exe -e me@example.com -d test1.example.com -d test2.example.com -p\n"
            + "This will automatically create and register account with email me@example.com, and\n"
            + "request the certificate for test1.example.com and test2.example.com, then import it into\n"
            + "Windows Certificate store (machine context), and finally set a Scheduled Task to manage renewal.\n\n"
            + "\"WinCertes.exe -d test1.example.com -d test2.example.com -r\" will revoke that certificate.";

        /// <summary>
        /// Checks whether the enrolled certificate should be renewed
        /// </summary>
        /// <param name="config">WinCertes config</param>
        /// <returns>true if certificate must be renewed or does not exists, false otherwise</returns>
        private static bool IsThereCertificateAndIsItToBeRenewed(List<string> domains)
        {
            string certificateExpirationDate = _config.ReadStringParameter("certExpDate" + Utils.DomainsToHostId(domains));
            _logger.Debug($"Current certificate expiration date is: {certificateExpirationDate}");
            if ((certificateExpirationDate == null) || (certificateExpirationDate.Length == 0)) { return true; }
            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
            DateTime expirationDate = DateTime.Parse(certificateExpirationDate);
            DateTime futureThresold = DateTime.Now.AddDays(_config.ReadIntParameter("renewalDays", 30));
            _logger.Debug($"Expiration Thresold Date after delay: {futureThresold.ToString()}");
            if (futureThresold > expirationDate) { return true; }
            return false;
        }

        /// <summary>
        /// Revoke certificate issued for specified list of domains
        /// </summary>
        /// <param name="domains"></param>
        private static void RevokeCert(List<string> domains)
        {
            string serial = _config.ReadStringParameter("certSerial" + Utils.DomainsToHostId(domains));
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
            var revRes = Task.Run(() => _certesWrapper.RevokeCertificate(cert)).GetAwaiter().GetResult();
            if (revRes)
            {
                _config.DeleteParameter("CertExpDate" + Utils.DomainsToHostId(domains));
                _config.DeleteParameter("CertSerial" + Utils.DomainsToHostId(domains));
                X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                store.Remove(cert);
                store.Close();
                _logger.Info($"Certificate with serial {serial} for domains {String.Join(",", domains)} has been successfully revoked");
            }
        }

        /// <summary>
        /// Initializes WinCertes Directory path
        /// </summary>
        private static void InitWinCertesDirectoryPath()
        {
            _winCertesPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + "\\WinCertes";
            if (!System.IO.Directory.Exists(_winCertesPath))
            {
                System.IO.Directory.CreateDirectory(_winCertesPath);
            }
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
            _config.WriteStringParameter("certExpDate" + Utils.DomainsToHostId(domains), certificate.GetExpirationDateString());
            _config.WriteStringParameter("certSerial" + Utils.DomainsToHostId(domains), certificate.GetSerialNumberString());
        }

        /// <summary>
        /// Initializes the CertesWrapper, and registers the account if necessary
        /// </summary>
        /// <param name="serviceUri">the ACME service URI</param>
        /// <param name="email">the email account used to register</param>
        private static void InitCertesWrapper(string serviceUri, string email)
        {
            // We get the CertesWrapper object, that will do most of the job.
            _certesWrapper = new CertesWrapper(serviceUri, email);

            // If local computer's account isn't registered on the ACME service, we'll do it.
            if (!_certesWrapper.IsAccountRegistered())
            {
                var regRes = Task.Run(() => _certesWrapper.RegisterNewAccount()).GetAwaiter().GetResult();
                if (!regRes) {
                    throw new Exception("Could not register ACME service account");
                }
            }
        }

        static void Main(string[] args)
        {
            // Main parameters with their default values
            WinCertesOptions winCertesOptions = new WinCertesOptions();
            List<string> domains = new List<string>();
            bool periodic = false;
            // Options that can be used by this application
            OptionSet options = new OptionSet()
            {
                { "s|service=", "the ACME Service URI to be used (optional, defaults to Let's Encrypt)", v => winCertesOptions.ServiceUri = v },
                { "e|email=", "the account email to be used for ACME requests (optional, defaults to no email)", v => winCertesOptions.Email = v },
                { "d|domain=", "the domain(s) to enroll (mandatory) *", v => domains.Add(v) },
                { "w|webroot=", "the web server root directory (optional, defaults to c:\\inetpub\\wwwroot)", v => winCertesOptions.WebRoot = v },
                { "p|periodic", "should WinCertes create the Windows Scheduler task to handle certificate renewal (default=no) *", v => periodic = (v != null) },
                { "b|bindname=", "IIS site name to bind the certificate to, e.g. \"Default Web Site\".", v => winCertesOptions.BindName = v },
                { "f|scriptfile=", "PowerShell Script file e.g. \"C:\\Temp\\script.ps1\" to execute upon successful enrollment (default=none)", v => winCertesOptions.ScriptFile = v },
                { "a|standalone", "should WinCertes create its own WebServer for validation (default=no). WARNING: it will use port 80", v => winCertesOptions.Standalone = (v != null) },
                { "r|revoke", "should WinCertes revoke the certificate identified by its domains (incompatible with other parameters except -d)", v => winCertesOptions.Revoke = (v != null) },
                { "k|csp=", "import the certificate into specified csp. By default WinCertes imports in the default CSP.", v => winCertesOptions.Csp = v }
            };
            // and the handling of these options
            List<string> res;
            try
            {
                res = options.Parse(args);
            } catch(Exception e)
            {
                Console.WriteLine("WinCertes.exe: " + e.Message);
                options.WriteOptionDescriptions(Console.Out);
                Console.WriteLine(_additionalInfo);
                return;
            }
            if (domains.Count==0)
            {
                Console.WriteLine("WinCertes.exe: At least one domain must be specified");
                options.WriteOptionDescriptions(Console.Out);
                Console.WriteLine(_additionalInfo);
                return;
            }
            domains.Sort();
            if (!Utils.IsAdministrator())
            {
                Console.WriteLine("WinCertes.exe must be launched as Administrator");
                return;
            }
            // Let's create the path where we will put the PFX files, and the log files
            InitWinCertesDirectoryPath();
            // Let's configure the logger
            Utils.ConfigureLogger(_winCertesPath);

            _config = new RegistryConfig();
            winCertesOptions.WriteOptionsIntoConfiguration(_config);

            // Is there an existing certificate that needs to be renewed ?
            if (!IsThereCertificateAndIsItToBeRenewed(domains) && !winCertesOptions.Revoke) {
                _logger.Debug("No need to renew certificate");
                if (periodic)
                {
                    Utils.CreateScheduledTask(Utils.DomainsToFriendlyName(domains), domains);
                }
                return;
            }

            try
            {
                // Initializing the CertesWrapper
                InitCertesWrapper(winCertesOptions.ServiceUri, winCertesOptions.Email);
            } catch (Exception e)
            {
                _logger.Error(e.Message);
                return;
            }

            if (winCertesOptions.Revoke)
            {
                RevokeCert(domains);
                return;
            }

            // Now the real stuff: we register the order for the domains, and have them validated by the ACME service
            IHTTPChallengeValidator challengeValidator = HTTPChallengeValidatorFactory.GetHTTPChallengeValidator(winCertesOptions.Standalone, winCertesOptions.WebRoot);
            var result = Task.Run(() => _certesWrapper.RegisterNewOrderAndVerify(domains, challengeValidator)).GetAwaiter().GetResult();
            if (!result) { return; }
            challengeValidator.EndAllChallengeValidations();

            // We get the certificate from the ACME service
            var pfxName = Task.Run(() => _certesWrapper.RetrieveCertificate(domains[0],_winCertesPath,Utils.DomainsToFriendlyName(domains))).GetAwaiter().GetResult();
            if (pfxName==null) { return; }
            AuthenticatedPFX pfx = new AuthenticatedPFX(_winCertesPath + "\\" + pfxName, _certesWrapper.PfxPassword);
            CertificateStorageManager certificateStorageManager = new CertificateStorageManager(pfx);
            certificateStorageManager.ProcessPFX((winCertesOptions.Csp == null));
            // and we write its information to the WinCertes configuration
            RegisterCertificateIntoConfiguration(certificateStorageManager.certificate, domains);
            // Import the certificate into the Windows store
            certificateStorageManager.ImportCertificateIntoCSP(winCertesOptions.Csp);

            // Bind certificate to IIS Site (won't do anything if option is null)
            Utils.BindCertificateForIISSite(certificateStorageManager.certificate, winCertesOptions.BindName);

            // Execute PowerShell Script (won't do anything if option is null)
            Utils.ExecutePowerShell(winCertesOptions.ScriptFile, pfx);
 
            // Should we create the AT task that will execute WinCertes periodically
            if (periodic)
            {
                Utils.CreateScheduledTask(Utils.DomainsToFriendlyName(domains), domains);
            }

            File.Delete(pfx.PfxFullPath);
            _logger.Info($"Removed PFX from filesystem: {pfxName}");
        }
    }
}
