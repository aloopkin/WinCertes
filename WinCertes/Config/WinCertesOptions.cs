using NLog;
using System;
using System.Collections.Generic;
using WinCertes.ChallengeValidator;
using Certes.Acme;
using Certes.Jws;
using Certes.Acme.Resource;
using Org.BouncyCastle.Asn1.X509.Qualified;

namespace WinCertes
{
    /// <summary>
    /// Class to handle the command line parameters given to WinCertes
    /// and merge with registry settings
    /// </summary>
    /// <remarks>
    /// WinCertesOptions has been extended significantly from https://github.com/aloopkin/WinCertes Thanks aloopkin for WinCertes.
    /// The interface now combines command line options and the new registry Certificate configuration store
    /// to support multiple certificates and re-use of command line options without repeating them on the command line.
    /// TODO: This is a work in progress.
    /// </remarks>
    internal class WinCertesOptions
    {
        private static readonly ILogger _logger = Program._logger;

        public RegistryConfig Registry { get; set; }

        public bool Initialised;

        public WinCertesOptions()
        {
            _logger.Debug("Initialising WinCertesOptions()...");
            Registry = new RegistryConfig(null);
            if (Registry.Initialised)
            {
                ReadOptionsFromConfiguration(Registry);
                IsNew = AccountKey == null && AccountEmail == null;
                Initialised = true;
            }
        }

        public WinCertesOptions(string certificateName)
        {
            _logger.Debug("Initialising WinCertesOptions({0})...", certificateName);
            Registry = new RegistryConfig(certificateName);
            CertificateName = certificateName;
            IsDefaultCertificate = false;
            if (Registry.Initialised)
            {
                ReadOptionsFromConfiguration(Registry);
                IsNew = AccountKey == null && AccountEmail == null && Domains.Count == 0 && !Registry.IsThereConfigParam("certExpDate");
                Initialised = true;
            }
        }

        #region Properties
        public string accountKey;
        public string BindName { get; set; }
        public string Csp { get; set; }
        private bool certificateChallenged;
        private bool certificateGenerated;
        public string CertificatePath { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + "\\WinCertes";
        public string CertificateName { get; set; }
        public List<string> Domains { get; set; } = new List<string>();
        private string accountEmail;
        public bool ExportPem { get; set; }
        public int HttpPort { get; set; } = 80;
        public bool IsDefaultCertificate { get; set; } = true;
        public bool IsNew { get; set; }
        public bool noCsp { get; set; }
        private string pfxPassword;
        public int Revoke { get; set; } = -1;
        private bool registered;
        private Uri serviceUri;
        public string ScriptFile { get; set; }
        public bool Standalone { get; set; }
        public int RenewalDelay { get; set; } = 30;
        public string WebRoot { get; set; }

        #endregion Properties

        #region PropertInterfaces

        /// <summary>
        /// The Private RSA Key is used to generate a certificate. It is also used with ACME registration
        /// and thus changing the key requires re-registration using the AccountEmail and ServiceUri again.
        /// </summary>
        public string AccountKey
        { 
            get
            {
                return accountKey;
            }

            set
            {
                if ( value != accountKey )
                {
                    accountKey = value;
                    if ( Initialised)
                    {
                        Program._logger.Info("Saving AccountKey to registry Certificate({0})", CertificateName);
                        Registry.WriteStringParameter("AccountKey", accountKey);
                        Registered = false;
                    }
                }
            }
        }

        /// <summary>
        /// LetsEncrypt account details. Any change to AccountEmail, Url, AccountKey may need re-registering
        /// </summary>
        public string AccountEmail
        {
            get
            {
                return accountEmail;
            }
            set
            {
                if (value == null || value.Length < 5 || value.IndexOf("@",StringComparison.InvariantCultureIgnoreCase) < 1 || value == accountEmail)
                    return;
                if (accountEmail == null)
                {
                    accountEmail = value;
                    return;
                }
                _logger.Debug("Updating AccountEmail from {0} to {1}", accountEmail, value);
                accountEmail = value;
                Registered = false;
            }
        }

        /// <summary>
        /// Registry key that indicates the certificate has been created, challenged and validated by Lets Encrypt.
        /// Any changes to the parameters will reset this indicator.
        /// </summary>
        public bool CertificateChallenged
        {
            get
            {
                return certificateChallenged;
            }
            set
            {
                if (value != certificateChallenged)
                {
                    certificateChallenged = value;
                    if (Initialised)
                    {
                        Registry.WriteBooleanParameter("CertificateChallenged", certificateChallenged);
                        if (certificateChallenged)
                            Program._logger.Info("The Certificate({0}) has been challenged successfully", CertificateName);
                    }
                }
            }
        }
        /// <summary>
        /// Registry key that indicates the certificate has been created, challenged and validated by Lets Encrypt.
        /// Any changes to the parameters will reset this indicator.
        /// </summary>
        public bool CertificateGenerated
        {
            get
            {
                return certificateGenerated;
            }
            set
            {
                if ( value != certificateGenerated )
                {
                    certificateGenerated = value;
                    if (Initialised)
                    {
                        Registry.WriteBooleanParameter("CertificateGenerated", certificateGenerated);
                        if (certificateGenerated)
                            Program._logger.Info("The Certificate({0}) has been generated successfully", CertificateName);
                    }
                }
            }
        }

        /// <summary>
        /// The password used to create the PFX certificate stored in IIS.
        /// If not provided from Registry or command line, a password is automatically generated.
        /// </summary>
        public string PfxPassword
        { 
            get
            {
                if (pfxPassword == null || pfxPassword.Length < 16)
                {
                    Program._logger.Warn("No password was provided or too short, generating random password");
                    pfxPassword = Guid.NewGuid().ToString("N").Substring(0, 16);
                    Registry.WriteStringParameter("PfxPassword", pfxPassword);
                }
                return pfxPassword;
            }
            set
            {
                if (value == null || value.Length < 16)
                    return;
                Program._logger.Warn("Saving PFX Password");
                pfxPassword = value;
                Registry.WriteStringParameter("PfxPassword", pfxPassword);
            }
        }
        public bool Registered 
        {
            get
            {
                return registered;
            }
            set
            {
                if ( value != registered )
                {
                    registered = value;
                    // Once registered, this needs to be saved to the registry Certificate store
                    SaveRegistration(registered);
                }
            }
        }

        /// <summary>
        /// Synchronised write of the registration information. Any change to the Uri or AccountEmail resets registration.
        /// </summary>
        /// <param name="registered"></param>
        private void SaveRegistration(bool registered)
        {
            if (!Initialised) return;

            if ( registered )
            {
                if (!Registry.ReadBooleanParameter("Registry", false))
                {
                    _logger.Info("Registered: updating AccountEmail, ServiceUri and Registered values in the Certificate Registry store({0})", CertificateName);
                    Registry.WriteBooleanParameter("Registered", registered);
                }
                if (Registry.ReadStringParameter("AccountEmail") != AccountEmail)
                {
                    _logger.Info("Registered: updating AccountEmail in the Certificate Registry store({0})", CertificateName);
                    Registry.WriteStringParameter("AccountEmail", AccountEmail);
                }
                string uri = ServiceUri.ToString();
                if (Registry.ReadStringParameter("ServiceUri") != uri)
                {
                    _logger.Info("Registered: updating ServiceUri in the Certificate Registry store({0})", CertificateName);
                    Registry.WriteStringParameter("ServiceUri", uri);
                }
            }
            else
            {
                if (Registry.ReadBooleanParameter("Registry", true))
                {
                    _logger.Info("Cancelling account registration");
                    Registry.WriteBooleanParameter("Registered", false);
                }
                CertificateGenerated = false;
            }
        }

        /// <summary>
        /// Encrypt Service URL. If the URL changes, then assume re-registration is required.
        /// </summary>
        public Uri ServiceUri
        {
            get
            {
                if (serviceUri == null)
                {
                    serviceUri = new Uri(WellKnownServers.LetsEncryptV2.ToString());
                    Registered = false;
                }
                return serviceUri;
            }
            set
            {
                if ( value != serviceUri )
                {
                    serviceUri = value;
                    if ( registered )
                        Registered = false;
                }
            }
        }

        #endregion PropertInterfaces

        #region DnsProperties
        // DNS Validation parameters are read from the registry, not supported on the command line so never written
        public string DNSValidatorType { get; set; }

        // DNSChallengeAcmeDnsValidator information. Registry ReadOnly
        public string DNSServerURL { get; set; }
        public string DNSServerUser { get; set; }
        public string DNSServerKey { get; set; }
        public string DNSServerSubDomain { get; set; }

        // DNSChallengeWinDnsValidator information. Registry Readonly
        public string DNSServerZone { get; set; }
        public string DNSServerPassword { get; set; }
        public string DNSServerHost { get; set; }
        #endregion DnsProperties

        #region Methods

        /// <summary>
        /// Read options from the registry, overwriting current settings.
        /// </summary>
        /// <remarks>CertificatePath is only ever read from the registry</remarks>
        /// <param name="config"></param>
        public void ReadOptionsFromConfiguration(IConfig config)
        {
            try
            {
                // Private key for the account
                AccountKey = config.ReadStringParameter("AccountKey", AccountKey);
                // Should we bind to IIS? If yes, let's do some config
                BindName = config.ReadStringParameter("BindName", BindName);
                // Let's store the CSP name, if any
                Csp = config.ReadStringParameter("CSP", Csp);
                // The location for storing exported certificates, this parameter
                // may be set manually in the registry
                CertificatePath = config.ReadStringParameter("CertificatePath", CertificatePath);
                // Certificate file name
                CertificateName = config.ReadStringParameter("CertificateName", CertificateName);
                // List of domains to register or already registered
                Domains = config.ReadStringListParameter("Domains", Domains).ConvertAll(d => d.ToLower());
                // write account email into conf, or reads from it, if any
                AccountEmail = config.ReadStringParameter("AccountEmail", AccountEmail);
                // Export the certificate and private key in PEM format
                ExportPem = config.ReadBooleanParameter("ExportPem", ExportPem);
                // Writing HTTP listening Port in conf
                HttpPort = config.ReadIntParameter("HttpPort", HttpPort);
                // Should we store certificate in the CSP?
                noCsp = config.ReadBooleanParameter("NoCsp", noCsp);
                // Password for the Certificate
                pfxPassword = config.ReadStringParameter("PfxPassword", pfxPassword);
                // Writing renewal delay to conf
                RenewalDelay = config.ReadIntParameter("RenewalDays", RenewalDelay);
                // The key has been registered
                registered = config.ReadBooleanParameter("Registered", registered);
                // Should we execute some PowerShell ? If yes, let's do some config
                ScriptFile = config.ReadStringParameter("ScriptFile", ScriptFile);
                // write service URI into conf, or reads from it, if any
                serviceUri = new Uri(config.ReadStringParameter("ServiceUri", WellKnownServers.LetsEncryptV2.ToString()));
                // Should we work with the built-in web server
                Standalone = config.ReadBooleanParameter("Standalone", Standalone);
                // do we have a webroot parameter to handle?
                WebRoot = config.ReadStringParameter("WebRoot", WebRoot);

                // DNS Validator parameters are manually created in the registry
                DNSValidatorType = config.ReadStringParameter("DNSValidatorType", DNSValidatorType);
                DNSServerURL = config.ReadStringParameter("DNSServerURL", DNSServerURL);
                DNSServerUser = config.ReadStringParameter("DNSServerUser", DNSServerUser);
                DNSServerKey = config.ReadStringParameter("DNSServerKey", DNSServerKey);
                DNSServerSubDomain = config.ReadStringParameter("DNSServerSubDomain", DNSServerSubDomain);
                DNSServerZone = config.ReadStringParameter("DNSServerZone", DNSServerZone);
                DNSServerPassword = config.ReadStringParameter("DNSServerPassword", DNSServerPassword);
                DNSServerHost = config.ReadStringParameter("DNSServerHost", DNSServerHost);
            }
            catch (Exception e)
            {
                _logger.Error($"Could not Read/Write command line parameters to configuration: {e.Message}");
            }
        }

        /// <summary>
        /// Create the Dns Registry keys if requested from the command line, even if null.
        /// These keys are not usually saved if null or empty. Force save using empty string.
        /// </summary>
        public void WriteDnsOptions()
        {
            Registry.WriteStringParameter("DNSValidatorType", DNSValidatorType == null ? "" : DNSValidatorType);
            Registry.WriteStringParameter("DNSServerURL", DNSServerURL == null ? "" : DNSServerURL);
            Registry.WriteStringParameter("DNSServerUser", DNSServerUser == null ? "" : DNSServerUser);
            Registry.WriteStringParameter("DNSServerKey", DNSServerKey == null ? "" : DNSServerKey);
            Registry.WriteStringParameter("DNSServerSubDomain", DNSServerSubDomain == null ? "" : DNSServerSubDomain);
            Registry.WriteStringParameter("DNSServerZone", DNSServerZone == null ? "" : DNSServerZone);
            Registry.WriteStringParameter("DNSServerPassword", DNSServerPassword == null ? "" : DNSServerPassword);
            Registry.WriteStringParameter("DNSServerHost", DNSServerHost == null ? "" : DNSServerHost);

        }
        /// <summary>
        /// Writes command line parameters into the specified config
        /// </summary>
        /// <remarks>CertificatePath is only ever read from the registry</remarks>
        /// <param name="config">the configuration object</param>
        public void WriteOptionsIntoConfiguration()
        {
            try
            {
                // Private key for the account
                AccountKey = Registry.WriteAndReadStringParameter("AccountKey", AccountKey, null);
                // Should we bind to IIS? If yes, let's do some config
                BindName = Registry.WriteAndReadStringParameter("BindName", BindName);
                // Let's store the CSP name, if any
                Csp = Registry.WriteAndReadStringParameter("CSP", Csp);
                // List of domains to register or already registered
                Domains = Registry.WriteAndReadStringListParameter("Domains", Domains).ConvertAll(d => d.ToLower());
                // write account email into conf, or reads from it, if any
                AccountEmail = Registry.WriteAndReadStringParameter("AccountEmail", AccountEmail);
                // Export the certificate and private key in PEM format
                ExportPem = Registry.WriteAndReadBooleanParameter("ExportPem", ExportPem);
                // Writing HTTP listening Port in conf
                HttpPort = Registry.WriteAndReadIntParameter("HttpPort", HttpPort, 80);
                // Should we store certificate in the CSP?
                noCsp = Registry.WriteAndReadBooleanParameter("NoCsp", noCsp);
                // Certificate file name
                CertificateChallenged = Registry.WriteAndReadBooleanParameter("CertificateChallenged", CertificateChallenged);
                CertificateGenerated = Registry.WriteAndReadBooleanParameter("CertificateGenerated", CertificateGenerated);
                CertificateName = Registry.WriteAndReadStringParameter("CertificateName", CertificateName);
                CertificatePath = Registry.WriteAndReadStringParameter("CertificatePath", CertificatePath);
                // Password for the Certificate
                PfxPassword = Registry.WriteAndReadStringParameter("PfxPassword", pfxPassword);
                // The key has been registered
                Registered = Registry.WriteAndReadBooleanParameter("Registered", Registered);
                // Writing renewal delay to conf
                RenewalDelay = Registry.WriteAndReadIntParameter("RenewalDays", RenewalDelay, 30);
                // Should we execute some PowerShell ? If yes, let's do some config
                ScriptFile = Registry.WriteAndReadStringParameter("ScriptFile", ScriptFile, null);
                // write service URI into conf, or reads from it, if any
                ServiceUri = new Uri(Registry.WriteAndReadStringParameter("ServiceUri", ServiceUri.ToString()));
                // Should we work with the built-in web server
                Standalone = Registry.WriteAndReadBooleanParameter("Standalone", Standalone);
                // do we have a webroot parameter to handle?
                WebRoot = Registry.WriteAndReadStringParameter("WebRoot", WebRoot);

                // DNS keys write if not null or empty string
                Registry.WriteAndReadStringParameter("DNSValidatorType", DNSValidatorType, "");
                Registry.WriteAndReadStringParameter("DNSServerURL", DNSServerURL, "");
                Registry.WriteAndReadStringParameter("DNSServerUser", DNSServerUser, "");
                Registry.WriteAndReadStringParameter("DNSServerKey", DNSServerKey, "");
                Registry.WriteAndReadStringParameter("DNSServerSubDomain", DNSServerSubDomain, "");
                Registry.WriteAndReadStringParameter("DNSServerZone", DNSServerZone, "");
                Registry.WriteAndReadStringParameter("DNSServerPassword", DNSServerPassword, "");
                Registry.WriteAndReadStringParameter("DNSServerHost", DNSServerHost, "");
            }
            catch (Exception e)
            {
                _logger.Error($"Could not Read/Write command line parameters to configuration: {e.Message}");
            }
        }

        /// <summary>
        /// Display the active options/settings for this Certificate as stored in the registry
        /// </summary>
        public void DisplayOptions()
        {
            _logger.Info("Displaying WinCertes current configuration:");
            _logger.Info("[{0}]", Registry.FullRegistryKey);
            IDNSChallengeValidator dnsChallengeValidator = DNSChallengeValidatorFactory.GetDNSChallengeValidator();
            string ui = ServiceUri.ToString();
            _logger.Info("Service URI:\t\t{0}", (ui == null) ? Certes.Acme.WellKnownServers.LetsEncryptV2.ToString() : ui);
            _logger.Info("Domain(s):\t\t{0}", Domains.Count > 0 ? string.Join(",", Domains) : "ERROR none specified");
            _logger.Info("Account Email:\t{0}", AccountEmail == null ? "ERROR not set" : AccountEmail);
            string accountKey = Registry.ReadStringParameter("AccountKey");
            _logger.Info("AccountKey:\t\t{0}", (accountKey == null || accountKey.Length < 1) ? "Account not registered" : "PrivateKey stored in registry" );
            _logger.Info("Registered:\t\t{0}", Registry.ReadIntParameter("Registered") == 1 ? "yes" : "no");
            _logger.Info("Generated:\t\t{0}", Registry.ReadIntParameter("Generated") == 1 ? "yes" : "no");
            if (dnsChallengeValidator != null)
            {
                _logger.Info("Auth. Mode:\t\tdns-01 validation");
            }
            else
            {
                _logger.Info("Auth. Mode:\t\t{0}", Standalone ? "http-01 validation standalone" : "http-01 validation with external web server");
                if (Standalone) _logger.Info("HTTP Port:\t\t{0}", HttpPort);
                else _logger.Info("Web Root:\t\t{0}", WebRoot != null ? WebRoot : Standalone ? "NA" : "ERROR: Missing" );
            }
            _logger.Info("IIS Bind Name:\t{0}", BindName ?? "none");
            _logger.Info("Import in CSP:\t{0}", Registry.IsThereConfigParam("noCsp") ? "no" : "yes");
            _logger.Info("PS Script File:\t{0}", ScriptFile ?? "none");
            _logger.Info("Renewal Delay:\t{0}", RenewalDelay + " days");
            _logger.Info("Task Scheduled:\t{0}", Utils.IsScheduledTaskCreated() ? "yes" : "no");
            _logger.Info("Cert Enrolled:\t{0}", Registry.IsThereConfigParam("certSerial") ? "yes" : "no");
        }

        #endregion Methods
    }
}