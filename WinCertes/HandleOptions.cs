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
    internal partial class Program
    {
        internal static WinCertesOptions _winCertesOptions;
        //internal static RegistryConfig _config;
        internal static bool _debug = false;
        internal static bool _creatednskeys = false;
        internal static bool _extra = false;
        internal static bool _periodic = false;
        internal static bool _reset = false;
        internal static bool _show = false;
        internal static OptionSet _options;

        internal static readonly int SUCCESS = 0;
        internal static readonly int ERROR = 1;
        internal static readonly int ERROR_INCORRECT_PARAMETER = 2;
        internal static readonly int ERROR_REGISTRY_FAILED = 3;
        internal static readonly int ERROR_BAD_CERTIFICATE_NAME = 4;
        internal static readonly int ERROR_NO_DOMAINS = 5;
        internal static readonly int ERROR_DOMAIN_CONFLICT = 6;
        internal static readonly int ERROR_NO_EMAIL = 7;
        internal static readonly int ERROR_REVOKE = 8;
        internal static readonly int ERROR_MISSING_HTTP_DNS = 9;

        /// <summary>
        /// Handles command line options. Command line options overwrite all settings saved in the Registry.
        /// </summary>
        /// <remarks>
        /// WinCertes settings are saved to the Registry. This information is used on subsequent runs to determine
        /// if registration has been completed and the private key assigned.
        /// 
        /// This implementation will place all configuration data for a Certificate into its own Registry SubKey.
        /// For backward compatibility and common defaults, the Registry root "WinCertes" is also used.
        /// 
        /// The unique certificate settings will be identified via the certificate name. i..e -n {name} or --certname {name}
        /// 
        /// The Certificate details will normally be stored in a SubKey, but for legacy support, an existing Certificate will
        /// be maintained under the root key.
        /// </remarks>
        /// <param name="args">the command line options</param>
        /// <returns>True if successful</returns>
        private static int HandleOptions(string[] args)
        {
            // Create the Default Base Registry Key for this certificate's configuration
            if (_winCertesOptions == null)
                _winCertesOptions = new WinCertesOptions(null);
            if (!_winCertesOptions.Registry.Initialised)
                return ERROR_REGISTRY_FAILED;

            string newName = null;
            List<string> _domains = new List<string>();
            bool areEquivalent;
            bool newDomainList;

            // Define the options that may be used by this application
            _options = new OptionSet() {
                { "n|certname=", "Unique Certificate name excluding file extension   e.g. \"wincertes.com\" (default=first domain name)", v => newName = v },
                { "s|service=", "ACME Service URI to be used (optional, defaults to Let's Encrypt)", v => _winCertesOptions.ServiceUri = new Uri(v) },
                { "e|email=", "Account email to be used for ACME requests  (optional, defaults to no email)", v => _winCertesOptions.AccountEmail = v },
                { "d|domain=", "Domain(s) to enroll (mandatory)", v => _domains.Add(v) },
                { "w|webserver:", "Toggles the local web server use and sets its {ROOT} directory (default c:\\inetpub\\wwwroot). Activates HTTP validation mode.", v => _winCertesOptions.WebRoot = v ?? "c:\\inetpub\\wwwroot" },
                { "p|periodic", "Should WinCertes create the Windows Scheduler task to handle certificate renewal (default=no)", v => _periodic = (v != null) },
                { "b|bindname=", "IIS site name to bind the certificate to,       e.g. \"Default Web Site\". Defaults to no binding.", v => _winCertesOptions.BindName = v },
                { "f|scriptfile=", "PowerShell Script file e.g. \"C:\\Temp\\script.ps1\" to execute upon successful enrollment (default=none)", v => _winCertesOptions.ScriptFile = v },
                { "x|exportcerts", "Should WinCertes export the certificates including PEM format.", v => _winCertesOptions.ExportPem = (v != null) },
                { "a|standalone", "Activate WinCertes internal WebServer for validation. Activates HTTP validation mode. WARNING: it will use port 80 unless -l is specified.", v => _winCertesOptions.Standalone = (v != null) },
                { "r|revoke:", "Should WinCertes revoke the certificate identified by its domains (to be used only with -d or -n). {REASON} is an optional integer between 0 and 5.", (int v) => _winCertesOptions.Revoke = v },
                { "k|csp=", "Import the certificate into specified csp. By default WinCertes imports in the default CSP.", v => _winCertesOptions.Csp = v },
                { "t|renewal=", "Trigger certificate renewal {N} days before expiration, default 30", (int v) => _winCertesOptions.RenewalDelay = v },
                { "l|listenport=", "Listen on port {N} in standalone mode (for use with -a switch, default 80)", (int v) => _winCertesOptions.HttpPort = v },
                { "dnscreatekeys", "Create all DNS values in the registry and exit. Use with --certname. Manually edit registry or include on command line", v=> _creatednskeys= (v != null ) },
                { "dnstype=", "DNS Validator type: acme-dns, win-dns", v => _winCertesOptions.DNSValidatorType = v },
                { "dnsurl=", "DNS Server URL: http://blah.net", v => _winCertesOptions.DNSServerURL = v },
                { "dnshost=", "DNS Server Host", v => _winCertesOptions.DNSServerHost = v },
                { "dnsuser=", "DNS Server Username", v => _winCertesOptions.DNSServerUser = v },
                { "dnspassword=", "DNS Server Password", v => _winCertesOptions.DNSServerPassword = v },
                { "dnskey=", "DNS Server Account Key", v => _winCertesOptions.DNSServerKey = v },
                { "dnssubdomain=", "DNS Server SubDomain", v => _winCertesOptions.DNSServerSubDomain = v },
                { "dnszone=", "DNS Server Zone", v => _winCertesOptions.DNSServerZone = v },
                { "debug", "Enable extra debug logging", v=> _debug= (v != null ) },
                { "extra", "Deprecated: Manages certificate name \"extra\". Please use -n instead", v=> _extra = (v != null ) },
                { "no-csp", "Disable import of the certificate into CSP. Use with caution, at your own risk. REVOCATION WILL NOT WORK IN THAT MODE.", v=> _winCertesOptions.noCsp = (v != null) },
                { "password=", "Certificate password min 16 characters (default=random)", v => _winCertesOptions.PfxPassword = v },
                { "reset", "Reset all configuration parameters for --certname and exit", v=> _reset = (v != null ) },
                { "show", "Show current configuration parameters and exit", v=> _show = (v != null ) }
            };

            // Merge options with default/existing configuration
            List<string> res;
            try
            {
                res = _options.Parse(args);
            }
            catch (Exception e)
            {
                WriteErrorMessageWithUsage(_options, e.Message);
                return ERROR;
            }

            // TODO increasing log level executes on the logger, but does not appear to take affect
            // so include --debug check in Utils.ConfigureLogger
            //_logger.Debug("Before log level chage: You should not see me");
            //if (_debug) Utils.SetLogLevel(LogLevel.Debug);
            //_logger.Debug("After enabling debug: You should see this message");

            if ( _winCertesOptions.IsNew && newName != null )
            {
                // We can skip backward compatibility checks and jump direct to the named Certificate store in registry
                _winCertesOptions.IsDefaultCertificate = false;
                _winCertesOptions.CertificateName = newName;
            }
            else
            {
                // Backward compatibility: Process default registry with command line parameters and adjust accordingly
                // Ideally we'd like to retire the original setup (default certificate & one extra)
                // by having all certificates in their own registry key.
                if (_extra)
                {
                    // Non default certificate
                    if (newName != null)
                    {
                        // Don't support both new and legacy certificate naming conventions on the command line
                        WriteErrorMessageWithUsage(_options, "Command line parameter --extra is deprecated, cannot use both --extra and --certname concurrently.");
                        return ERROR_BAD_CERTIFICATE_NAME;
                    }
                    else
                    {
                        // Legacy support for "extra"
                        newName = "extra";
                        _winCertesOptions.CertificateName = newName;
                        // Force registry reload - create new Certificate store
                        _winCertesOptions.IsDefaultCertificate = false;
                    }
                }
                else
                {
                    // There should always be a certificate name, even for the default RegistryKey
                    if (_winCertesOptions.CertificateName == null && newName == null)
                    {
                        if (_domains.Count != 0)
                        {
                            _winCertesOptions.CertificateName = _domains[0];
                        }
                        else if (_winCertesOptions.Domains.Count != 0)
                        {
                            _winCertesOptions.CertificateName = _winCertesOptions.Domains[0];
                        }
                    }
                    // Check if correct registry key was merged. Certifiate uniqueness is based on domain name list
                    // If nothing exists, this should trigger all certificates to have a unique Certificate store in registry
                    areEquivalent = (_winCertesOptions.Domains.Count == _domains.Count) && !_winCertesOptions.Domains.Except(_domains).Any();
                    newDomainList = (_winCertesOptions.Domains.Count == 0 && _domains.Count > 0);

                    if (areEquivalent)
                    {
                        // New or default certificate
                        if (_winCertesOptions.Domains.Count == 0)
                        {
                            if (newName != null)
                            {
                                // Named certificate requested, trigger reload for the new certificate store. 
                                // i.e. Only the certname was provided on the command line and nothing in defaults (as expected for new setup)
                                _winCertesOptions.IsDefaultCertificate = false;
                            }
                            else
                            {
                                WriteErrorMessageWithUsage(_options, "Insufficient parameters. Please provide Certificate name, domain name(s), or manually configure the registry key");
                                return ERROR_NO_DOMAINS;
                            }
                        }
                        // New, or same certificate domain(s) , apply new name from command line (even if null)
                        _winCertesOptions.CertificateName = newName;
                    }
                    else
                    {
                        // Registry and command line Domain list is different.
                        if (!newDomainList)
                        {
                            WriteErrorMessageWithUsage(_options, "Command line parameters do not match WinCertes registry key. Delete key values or correct command line parameters.");
                            return ERROR_DOMAIN_CONFLICT;
                        }

                        // Different domain name list: New Registry Certificate store is required, but command line name matches default certificate
                        if (newName == _winCertesOptions.CertificateName)
                        {
                            WriteErrorMessageWithUsage(_options, "Certname is used by default Certificate but the domain list has changed. Use a new name or delete existing Domains list from the WinCertes registry key");
                            return ERROR_BAD_CERTIFICATE_NAME;
                        }

                        // Trigger use of new Certificate store and reload
                        _winCertesOptions.IsDefaultCertificate = false;
                    }
                }
            }

            //
            // If there has been a change reload and once the certificate has a name, always use the subkey.
            //
            if (!_winCertesOptions.IsDefaultCertificate)
            {
                // This is not the default certificate, reload from new Certificate store, create if needed
                _winCertesOptions = new WinCertesOptions(_winCertesOptions.CertificateName);

                // Overwrite registry subkey from command line options again
                _domains = new List<string>();
                res = _options.Parse(args);

                // No need to do any more checks if resetting
                if (_reset) return SUCCESS;

                // Helper to create the DNS keys
                if ( _creatednskeys )
                {
                    return SUCCESS;
                }

                // Domain check
                areEquivalent = (_winCertesOptions.Domains.Count == _domains.Count) && !_winCertesOptions.Domains.Except(_domains).Any();
                newDomainList = (_winCertesOptions.Domains.Count == 0 && _domains.Count > 0);

                // Is the new Certificate settings compatible or new?
                if (areEquivalent)
                {
                    // No info
                    if (_domains.Count == 0)
                    {
                        WriteErrorMessageWithUsage(_options, "At least one domain must be specified on the command line for a new certificate");
                        return ERROR_NO_DOMAINS;
                    }
                    // Existing and matching domain list - OK
                }
                else
                {
                    if (newDomainList)
                    {
                        // New Certificate
                        _winCertesOptions.Domains = _domains.ConvertAll(d => d.ToLower());
                    }
                    else
                    {
                        // Domain list is different. So need a new name or delete the registry certificate key
                        WriteErrorMessageWithUsage(_options, "The domain list has changed for this certificate key \"" + _winCertesOptions.CertificateName + "\"");
                        return ERROR_BAD_CERTIFICATE_NAME;
                    }
                }
            }

            //
            // Final validation
            //
            if (_winCertesOptions.Revoke > 5)
            {
                WriteErrorMessageWithUsage(_options, "Revocation Reason is a number between 0 and 5");
                return ERROR_REVOKE;
            }
            if ( _winCertesOptions.AccountEmail == null || _winCertesOptions.AccountEmail.Length < 5 )
            {
                WriteErrorMessageWithUsage(_options, "An email address needs to be provided or stored in the registry");
                return ERROR_NO_EMAIL;

            }
            // Final check
            if ((!_show) && (!_reset) && (_winCertesOptions.Domains.Count == 0))
            {
                WriteErrorMessageWithUsage(_options, "At least one domain must be specified");
                return ERROR_NO_DOMAINS;
            }

            return SUCCESS;
        }


        /// <summary>
        /// Writes the error message when handling options
        /// </summary>
        /// <param name="options">Command line options OptionSet</param>
        /// <param name="message">Error description</param>
        private static void WriteErrorMessageWithUsage(OptionSet options, string message)
        {
            string err = "ERROR: " + message;
            string exampleUsage = err + "\nTypical usage:\n\n"
                + "  \"WinCertes.exe -a -e me@example.com -d test1.example.com -d test2.example.com -p\"\n\n"
                + "This will automatically create and register account with email me@example.com, and\n"
                + "request the certificate for (test1.example.com, test2.example.com), then import it\n"
                + "into Windows Certificate store, create a Scheduled Task to manage renewal, then save\n"
                + "settings to registry [HKLM\\SOFTWARE\\WinCertes\\test1.example.com]. Once the settings\n"
                + "are saved to registry WinCertes.exe may be run with -n test1.example.com to re-use\n"
                + "the same settings. e.g.\n\n"
                + "  \"WinCertes.exe -n test1.example.com\" will renew that certificate.\n"
                + "  \"WinCertes.exe -n test1.example.com -r\" will revoke that certificate.\n\n"
                + "Be sure to revoke a certificate before deleting registry keys via --reset\n\n"
                + "  \"WinCertes.exe -n test1.example.com --reset\" will revoke that certificate.\n\n"
                + "For debugging use: -s https://acme-staging-v02.api.letsencrypt.org/directory\n\n";
            _logger.Error(exampleUsage);
            StringWriter o = new StringWriter();
            o.WriteLine("WinCertes.exe Usage:\n");
            options.WriteOptionDescriptions(o);
            _logger.Error(o);
            if (_show || _debug) _winCertesOptions.DisplayOptions();
            // Repeat the message because few will scroll up
            _logger.Error(err);
        }

    }
}