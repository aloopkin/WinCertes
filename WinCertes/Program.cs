using Mono.Options;
using NLog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using WinCertes.ChallengeValidator;

namespace WinCertes
{
    /// <summary>
    /// Class to handle the command line parameters given to WinCertes
    /// </summary>
    class WinCertesOptions
    {
        private static readonly ILogger _logger = LogManager.GetLogger("WinCertes.WinCertesOptions");

        public WinCertesOptions()
        {
            ServiceUri = null;
            Email = null;
            WebRoot = null;
            BindName = null;
            ScriptFile = null;
            Standalone = false;
            Revoke = -1;
            Csp = null;
            noCsp = false;
            RenewalDelay = 30;
            HttpPort = 80;
        }
        public string ServiceUri { get; set; }
        public string Email { get; set; }
        public string WebRoot { get; set; }
        public string BindName { get; set; }
        public string ScriptFile { get; set; }
        public bool Standalone { get; set; }
        public int Revoke { get; set; }
        public string Csp { get; set; }
        public bool noCsp { get; set; }
        public int RenewalDelay { get; set; }
        public int HttpPort { get; set; }
        public Dictionary<string, string> MiscOpts { get; set; }

        /// <summary>
        /// Writes command line parameters into the specified config
        /// </summary>
        /// <param name="config">the configuration object</param>
        public void WriteOptionsIntoConfiguration(IConfig config)
        {
            try
            {
                // write service URI into conf, or reads from it, if any
                ServiceUri = config.WriteAndReadStringParameter("serviceUri", ServiceUri);
                // write account email into conf, or reads from it, if any
                Email = config.WriteAndReadStringParameter("accountEmail", Email);
                // Should we work with the built-in web server
                Standalone = config.WriteAndReadBooleanParameter("standalone", Standalone);
                // do we have a webroot parameter to handle?
                WebRoot = config.WriteAndReadStringParameter("webRoot", WebRoot);
                // Should we bind to IIS? If yes, let's do some config
                BindName = config.WriteAndReadStringParameter("bindName", BindName);
                // Should we execute some PowerShell ? If yes, let's do some config
                ScriptFile = config.WriteAndReadStringParameter("scriptFile", ScriptFile);
                // Writing renewal delay to conf
                RenewalDelay = config.WriteAndReadIntParameter("renewalDays", RenewalDelay, 30);
                // Writing HTTP listening Port in conf
                HttpPort = config.WriteAndReadIntParameter("httpPort", HttpPort, 80);
                // Should we store certificate in the CSP?
                noCsp = config.WriteAndReadBooleanParameter("noCsp", noCsp);
                // Let's store the CSP name, if any
                Csp = config.WriteAndReadStringParameter("CSP", Csp);
                foreach(KeyValuePair<string, string> miscOpt in MiscOpts)
                {
                    if (miscOpt.Value.All(char.IsDigit))
                        config.WriteIntParameter(miscOpt.Key, int.Parse(miscOpt.Value));
                    else
                        config.WriteStringParameter(miscOpt.Key, miscOpt.Value);
                }
            }
            catch (Exception e)
            {
                _logger.Error($"Could not Read/Write command line parameters to configuration: {e.Message}");
            }
        }

        public void displayOptions(IConfig config)
        {
            if (!config.isThereConfigParam("accountKey"))
            {
                Console.WriteLine("WinCertes is not configured yet");
                return;
            }
            IDNSChallengeValidator dnsChallengeValidator = DNSChallengeValidatorFactory.GetDNSChallengeValidator(config);
            Console.WriteLine("Service URI:\t" + ((ServiceUri == null) ? Certes.Acme.WellKnownServers.LetsEncryptV2.ToString() : ServiceUri));
            Console.WriteLine("Account Email:\t" + Email);
            Console.WriteLine("Registered:\t" + (config.ReadIntParameter("registered") == 1 ? "yes" : "no"));
            if (dnsChallengeValidator != null)
            {
                Console.WriteLine("Auth. Mode:\tdns-01 validation");
            }
            else
            {
                Console.WriteLine("Auth. Mode:\t" + (Standalone ? "http-01 validation standalone" : "http-01 validation with external web server"));
                if (Standalone) Console.WriteLine("HTTP Port:\t" + HttpPort);
                else Console.WriteLine("Web Root:\t" + WebRoot);
            }
            Console.WriteLine("IIS Bind Name:\t" + (BindName ?? "none"));
            Console.WriteLine("Import in CSP:\t" + (config.isThereConfigParam("noCsp") ? "no" : "yes"));
            Console.WriteLine("PS Script File:\t" + (ScriptFile ?? "none"));
            Console.WriteLine("Renewal Delay:\t" + RenewalDelay + " days");
            Console.WriteLine("Task Scheduled:\t" + (Utils.IsScheduledTaskCreated() ? "yes" : "no"));
            Console.WriteLine("Cert Enrolled:\t" + (config.isThereConfigParam("certSerial") ? "yes" : "no"));
        }
    }

    class Program
    {
        private static readonly ILogger _logger = LogManager.GetLogger("WinCertes");

        private static CertesWrapper _certesWrapper;
        private static IConfig _config;
        private static string _winCertesPath;
        private static string _certTmpPath;
        private static WinCertesOptions _winCertesOptions;
        private static List<string> _domains;
        private static bool _periodic = false;
        private static bool _show = false;
        private static bool _reset = false;
        private static int _extra = -1;
        private static OptionSet _options;
 
        private static readonly int ERROR = 1;
        private static readonly int ERROR_INCORRECT_PARAMETER = 2;

        /// <summary>
        /// Handles command line options
        /// </summary>
        /// <param name="args">the command line options</param>
        /// <returns></returns>
        private static bool HandleOptions(string[] args)
        {
            _domains = new List<string>();
            _winCertesOptions.MiscOpts = new Dictionary<string, string>();

            // Options that can be used by this application
            _options = new OptionSet() {
                { "s|service=", "the ACME Service URI to be used (optional, defaults to Let's Encrypt)", v => _winCertesOptions.ServiceUri = v },
                { "e|email=", "the account email to be used for ACME requests (optional, defaults to no email)", v => _winCertesOptions.Email = v },
                { "d|domain=", "the domain(s) to enroll (mandatory)", v => _domains.Add(v) },
                { "w|webserver:", "toggles the local web server use and sets its {ROOT} directory (default c:\\inetpub\\wwwroot). Activates HTTP validation mode.", v => _winCertesOptions.WebRoot = v ?? "c:\\inetpub\\wwwroot" },
                { "p|periodic", "should WinCertes create the Windows Scheduler task to handle certificate renewal (default=no)", v => _periodic = (v != null) },
                { "b|bindname=", "IIS site name to bind the certificate to, e.g. \"Default Web Site\". Defaults to no binding.", v => _winCertesOptions.BindName = v },
                { "f|scriptfile=", "PowerShell Script file e.g. \"C:\\Temp\\script.ps1\" to execute upon successful enrollment (default=none)", v => _winCertesOptions.ScriptFile = v },
                { "a|standalone", "should WinCertes create its own WebServer for validation. Activates HTTP validation mode. WARNING: it will use port 80 unless -l is specified.", v => _winCertesOptions.Standalone = (v != null) },
                { "r|revoke:", "should WinCertes revoke the certificate identified by its domains (to be used only with -d). {REASON} is an optional integer between 0 and 5.", (int v) => _winCertesOptions.Revoke = v },
                { "k|csp=", "import the certificate into specified csp. By default WinCertes imports in the default CSP.", v => _winCertesOptions.Csp = v },
                { "t|renewal=", "trigger certificate renewal {N} days before expiration, default 30", (int v) => _winCertesOptions.RenewalDelay = v },
                { "l|listenport=", "listen on port {N} in standalone mode (for use with -a switch, default 80)", (int v) => _winCertesOptions.HttpPort = v },
                { "show", "show current configuration parameters", v=> _show = (v != null ) },
                { "reset", "reset all configuration parameters", v=> _reset = (v != null ) },
                { "extra:", "manages additional certificate(s) instead of the default one, with its own settings. Add an integer index optionally to manage more certs.", (int v) => _extra = v },
                { "no-csp", "does not import the certificate into CSP. Use with caution, at your own risks. REVOCATION WILL NOT WORK IN THAT MODE.", v=> _winCertesOptions.noCsp = (v != null) },
                { "setopt={:}", "sets configuration options in the form key:value.", (k,v) => _winCertesOptions.MiscOpts.Add(k,v)  }
            };

            // and the handling of these options
            List<string> res;
            try
            {
                res = _options.Parse(args);
            }
            catch (Exception e) { WriteErrorMessageWithUsage(_options, e.Message); return false; }
            if ((!_show) && (!_reset) && (_domains.Count == 0)) { WriteErrorMessageWithUsage(_options, "At least one domain must be specified"); return false; }
            if (_winCertesOptions.Revoke > 5) { WriteErrorMessageWithUsage(_options, "Revocation Reason is a number between 0 and 5"); return false; }
            _domains = _domains.ConvertAll(d => d.ToLower());
            return true;
        }

        /// <summary>
        /// Writes the error message when handling options
        /// </summary>
        /// <param name="options"></param>
        /// <param name="message"></param>
        private static void WriteErrorMessageWithUsage(OptionSet options, string message)
        {
            string exampleUsage = "\nTypical usage: WinCertes.exe -a -e me@example.com -d test1.example.com -d test2.example.com -p\n"
                + "This will automatically create and register account with email me@example.com, and\n"
                + "request the certificate for test1.example.com and test2.example.com, then import it into\n"
                + "Windows Certificate store (machine context), and finally set a Scheduled Task to manage renewal.\n\n"
                + "\"WinCertes.exe -d test1.example.com -d test2.example.com -r\" will revoke that certificate.";
            Console.WriteLine("WinCertes.exe:" + message);
            options.WriteOptionDescriptions(Console.Out);
            Console.WriteLine(exampleUsage);
        }

        /// <summary>
        /// Checks whether the enrolled certificate should be renewed
        /// </summary>
        /// <param name="config">WinCertes config</param>
        /// <returns>true if certificate must be renewed or does not exists, false otherwise</returns>
        private static bool IsThereCertificateAndIsItToBeRenewed(List<string> domains)
        {
            string certificateExpirationDate = _config.ReadStringParameter("certExpDate" + Utils.DomainsToHostId(domains));
            _logger.Debug($"Current certificate expiration date is: {certificateExpirationDate}");
            if ((certificateExpirationDate == null) || (certificateExpirationDate.Length == 0)) return true;
            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
            DateTime expirationDate = DateTime.Parse(certificateExpirationDate);
            DateTime futureThresold = DateTime.Now.AddDays(_config.ReadIntParameter("renewalDays", 30));
            _logger.Debug($"Expiration Thresold Date after delay: {futureThresold.ToString()}");
            if (futureThresold > expirationDate) return true;
            _logger.Debug("Certificate exists and does not need to be renewed");
            return false;
        }

        /// <summary>
        /// Revoke certificate issued for specified list of domains
        /// </summary>
        /// <param name="domains"></param>
        private static void RevokeCert(List<string> domains, int revoke)
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
            // Here we revoke from ACME Service. Note that any error is already handled into the wrapper
            if (Task.Run(() => _certesWrapper.RevokeCertificate(cert, revoke)).GetAwaiter().GetResult())
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
        /// Initializes WinCertes Directory path on the filesystem
        /// </summary>
        private static void InitWinCertesDirectoryPath()
        {
            _winCertesPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + "\\WinCertes";
            if (!System.IO.Directory.Exists(_winCertesPath))
            {
                System.IO.Directory.CreateDirectory(_winCertesPath);
            }
            _certTmpPath = _winCertesPath + "\\CertsTmp";
            if (!System.IO.Directory.Exists(_certTmpPath))
            {
                System.IO.Directory.CreateDirectory(_certTmpPath);
            }
            // We fix the permissions for the certs temporary directory
            // so that no user can have access to it
            DirectoryInfo winCertesTmpDi = new DirectoryInfo(_certTmpPath);
            DirectoryInfo programDataDi = new DirectoryInfo(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            DirectorySecurity programDataDs = programDataDi.GetAccessControl(AccessControlSections.All);
            DirectorySecurity winCertesTmpDs = winCertesTmpDi.GetAccessControl(AccessControlSections.All);
            winCertesTmpDs.SetAccessRuleProtection(true, false);
            foreach (FileSystemAccessRule accessRule in programDataDs.GetAccessRules(true, true, typeof(NTAccount)))
            {
                if (accessRule.IdentityReference.Value.IndexOf("Users", StringComparison.InvariantCultureIgnoreCase) < 0)
                {
                    winCertesTmpDs.AddAccessRule(accessRule);
                }
            }
            winCertesTmpDi.SetAccessControl(winCertesTmpDs);
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
        private static void InitCertesWrapper(RegistryConfig config, string serviceUri, string email)
        {
            // We get the CertesWrapper object, that will do most of the job.
            _certesWrapper = new CertesWrapper(config, serviceUri, email);

            // If local computer's account isn't registered on the ACME service, we'll do it.
            if (!_certesWrapper.IsAccountRegistered())
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
        private static void RemoveFileAndLog(AuthenticatedPFX pfx)
        {
            File.Delete(pfx.PfxFullPath);
            File.Delete(pfx.PemCertPath);
            File.Delete(pfx.PemKeyPath);
            _logger.Info($"Removed files from filesystem: {pfx.PfxFullPath}, {pfx.PemCertPath}, {pfx.PemKeyPath}");
        }

        static int Main(string[] args)
        {
            // Main parameters with their default values
            string taskName = null;
            _winCertesOptions = new WinCertesOptions();

            if (!Utils.IsAdministrator()) { Console.WriteLine("WinCertes.exe must be launched as Administrator"); return ERROR; }
            // Command line options handling and initialization stuff
            if (!HandleOptions(args)) return ERROR_INCORRECT_PARAMETER;
            if (_periodic) taskName = Utils.DomainsToFriendlyName(_domains);
            InitWinCertesDirectoryPath();
            Utils.ConfigureLogger(_winCertesPath);
            var registryConfig = new RegistryConfig(_extra);
            _config = registryConfig;
            _winCertesOptions.WriteOptionsIntoConfiguration(_config);
            if (_show) { _winCertesOptions.displayOptions(_config); return 0; }

            // Reset is a full reset !
            if (_reset)
            {
                IConfig baseConfig = new RegistryConfig(-1);
                baseConfig.DeleteAllParameters();
                Utils.DeleteScheduledTasks();
                return 0;
            }

            // Initialization and renewal/revocation handling
            try
            {
                InitCertesWrapper(registryConfig, _winCertesOptions.ServiceUri, _winCertesOptions.Email);
            }
            catch (Exception e) { _logger.Error(e.Message); return ERROR; }
            if (_winCertesOptions.Revoke > -1) { RevokeCert(_domains, _winCertesOptions.Revoke); return 0; }
            // default mode: enrollment/renewal. check if there's something to be done
            // note that in any case, we want to be able to set the scheduled task (won't do anything if taskName is null)
            if (!IsThereCertificateAndIsItToBeRenewed(_domains)) { Utils.CreateScheduledTask(taskName, _domains, _extra); return 0; }

            // Now the real stuff: we register the order for the domains, and have them validated by the ACME service
            IHTTPChallengeValidator httpChallengeValidator = HTTPChallengeValidatorFactory.GetHTTPChallengeValidator(_winCertesOptions.Standalone, _winCertesOptions.HttpPort, _winCertesOptions.WebRoot);
            IDNSChallengeValidator dnsChallengeValidator = DNSChallengeValidatorFactory.GetDNSChallengeValidator(_config);
            if ((httpChallengeValidator == null) && (dnsChallengeValidator == null)) { WriteErrorMessageWithUsage(_options, "Specify either an HTTP or a DNS validation method."); return ERROR_INCORRECT_PARAMETER; }
            if (!(Task.Run(() => _certesWrapper.RegisterNewOrderAndVerify(_domains, httpChallengeValidator, dnsChallengeValidator)).GetAwaiter().GetResult())) { if (httpChallengeValidator != null) httpChallengeValidator.EndAllChallengeValidations(); return ERROR; }
            if (httpChallengeValidator != null) httpChallengeValidator.EndAllChallengeValidations();

            // We get the certificate from the ACME service
            var pfx = Task.Run(() => _certesWrapper.RetrieveCertificate(_domains, _certTmpPath, Utils.DomainsToFriendlyName(_domains))).GetAwaiter().GetResult();
            if (pfx == null) return ERROR;
            CertificateStorageManager certificateStorageManager = new CertificateStorageManager(pfx, ((_winCertesOptions.Csp == null) && (!_winCertesOptions.noCsp)));
            // Let's process the PFX into Windows Certificate objet.
            certificateStorageManager.ProcessPFX();
            // and we write its information to the WinCertes configuration
            RegisterCertificateIntoConfiguration(certificateStorageManager.Certificate, _domains);
            // Import the certificate into the Windows store
            if (!_winCertesOptions.noCsp) certificateStorageManager.ImportCertificateIntoCSP(_winCertesOptions.Csp);

            // Bind certificate to IIS Site (won't do anything if option is null)
            Utils.BindCertificateForIISSite(certificateStorageManager.Certificate, _winCertesOptions.BindName);
            // Execute PowerShell Script (won't do anything if option is null)
            Utils.ExecutePowerShell(_winCertesOptions.ScriptFile, pfx);
            // Create the AT task that will execute WinCertes periodically (won't do anything if taskName is null)
            Utils.CreateScheduledTask(taskName, _domains, _extra);

            // Let's delete the PFX file
            RemoveFileAndLog(pfx);

            return 0;
        }
    }
}
