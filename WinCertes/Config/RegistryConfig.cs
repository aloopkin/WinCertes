using Microsoft.Win32;
using NLog;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml.Xsl;

namespace WinCertes
{
    /// <summary>
    /// Configuration class, managing WinCertes configuration into Windows Registry
    /// </summary>
    public class RegistryConfig : IConfig
    {
        private static readonly ILogger _logger = Program._logger;
        private static string _registrySoftware = @"HKEY_LOCAL_MACHINE\SOFTWARE\";
        private static string _subKeyBase = @"SOFTWARE\";
        private static string _keyBaseName = "WinCertes";
        /// <summary>
        /// CertificateStore SubKey Name. e.g. mycertificate.com
        /// </summary>
        public string CertificateStore { get; set; }
        /// <summary>
        /// Absolute Registry Key. e.g. HKEY_LOCAL_MACHINE\SOFTWARE\
        /// </summary>
        public string FullRegistryKey { get; set; }  = _registrySoftware + _keyBaseName;

        /// <summary>
        /// Full key path within HKLM. e.g. SOFTWARE\WinCertes\mycertificate.com
        /// </summary>
        public string HKLMRegistryKey { get; set; } = _subKeyBase + _keyBaseName;

        public string HKLMCertificateParent { get; set; } = _subKeyBase;

        public bool Initialised;

        /// <summary>
        /// Class constructor. Create and set security permissions on the WinCertes registry key and provide a read/write
        /// interface to that key.
        /// If <code>certificateStore</code> to create a subkey for the certificate being processed. This is preferred.
        /// </summary>
        /// <remarks>
        /// If <code>certificateStore</code> is provided a sub key is created to store all information about this specific
        /// certificate. 
        /// <code>extra=true</code> provides legacy support for the --extra command line parameter. This is synonomouse
        /// with <code>certificateStore="extra"</code>
        /// Registry security restricted to Administrators, no exceptions
        /// </remarks>
        /// <param name="certificateStore">Name of subkey to store certificate information if more than one certificate
        /// is managed by WinCertes on this computer</param>
        public RegistryConfig(string certificateStore = null)
        {
            Initialise(certificateStore);
        }

        /// <summary>
        /// Legacy Class constructor. if extra = false, builds the base config. if extra = true, builds the extra certificate config.
        /// This constructor will be deprecated. See <code>RegistryConfig(string certificateStore = null)</code>
        /// </summary>
        /// <remarks>
        /// If <code>certificateStore</code> is provided a sub key is created to store all information about this specific
        /// certificate. <code>extra=true</code> provides legacy support for the "extra" sub key.
        /// <code>extra</code> will be deprecated by CertificateStore in a future release
        /// Registry security restricted to Administrators, no exceptions
        /// </remarks>
        /// <param name="extra">True to store the certificate information undre a subkey "extra"</param>
        public RegistryConfig(bool extra = false)
        {
            if ( extra )
            Initialise("extra");
            else
                Initialise(null);
        }

        /// <summary>
        /// Class constructor. <code>certificateStore</code> specifies the name of the certificate being managed.
        /// </summary>
        /// <remarks>
        /// If <code>certificateStore</code> is provided a sub key is created to store all information about this specific
        /// certificate. <code>extra=true</code> provides legacy support for the "extra" certificate store sub key.
        /// Registry security is enforced from the parent HKLM\Software minus Users.
        /// No support is provided for any credentials like "MyDomain\Certificate Users" as it hits the *users* filter.
        /// </remarks>
        /// <param name="certificateStore">Name of subkey to store certificate information if more than one certificate
        /// is managed by WinCertes on this computer</param>
        private void Initialise(string certificateStore = null)
        {
            try
            {
                //
                // HKLM WinCertes key is for Administrative access only.
                // Manage access rights by using parent permissions from HKLM\Software and remove user permissions.
                //
                RegistryKey keySoftware = Registry.LocalMachine.OpenSubKey("SOFTWARE",true); 
                RegistrySecurity security = keySoftware.GetAccessControl(AccessControlSections.Access);

                RegistryKey keyWinCertes = keySoftware.OpenSubKey(_keyBaseName,true);
                if (keyWinCertes == null)
                {
                    _logger.Info("Creating new Registry Key {0}", _keyBaseName);
                    keyWinCertes = keySoftware.CreateSubKey(_keyBaseName, RegistryKeyPermissionCheck.ReadWriteSubTree);
                }
                // Remove inheritance - also deletes all inherited rules
                RegistrySecurity securityWinCertes = keyWinCertes.GetAccessControl(AccessControlSections.All);
                securityWinCertes.SetAccessRuleProtection(true, false);
                // Copy rules from parent, except user access
                foreach (RegistryAccessRule rule in security.GetAccessRules(true, true, typeof(NTAccount)))
                {
                    try
                    {
                        // Copy all relevant rules except user
                        if (rule.IdentityReference.Value.IndexOf("Users", StringComparison.InvariantCultureIgnoreCase) < 0)
                        {
                            securityWinCertes.AddAccessRule(rule);
                        }
                    }
                    catch { }
                }
                keyWinCertes.SetAccessControl(securityWinCertes);
#if DEBUG
                //ShowSecurity(securityWinCertes);
#endif
                //
                // Now manage the certificate store
                //
                CertificateStore = certificateStore;
                if (certificateStore != null )
                {
                    if (keyWinCertes.OpenSubKey(certificateStore,true) == null)
                    {
                        _logger.Debug("Creating SubKey '{0}'", certificateStore);
                        keyWinCertes.CreateSubKey(certificateStore, true);
                        keyWinCertes.SetAccessControl(securityWinCertes);
                    }
                    FullRegistryKey += @"\" + certificateStore;
                    HKLMRegistryKey += @"\" + certificateStore;
                    HKLMCertificateParent += @"\" + _keyBaseName;
                }
                Initialised = true;
             }
            catch (Exception e)
            {
                _logger.Warn(e,$"Warning: Could not open/create registry subkey: {e.Message}. We'll try to continue anyway.");
            }
        }

        /// <summary>
        /// Utility to display security rules
        /// </summary>
        /// <param name="security">RegistrySecurity object from the RegistryKey</param>
        private static void ShowSecurity(RegistrySecurity security)
        {
            _logger.Info("Current access rules:");
            foreach (RegistryAccessRule rule in security.GetAccessRules(true, true, typeof(NTAccount)))
            {
                _logger.Info("        User: {0}", rule.IdentityReference);
                _logger.Info("        Type: {0}", rule.AccessControlType);
                _logger.Info("      Rights: {0}", rule.RegistryRights);
                _logger.Info(" Inheritance: {0}", rule.InheritanceFlags);
                _logger.Info(" Propagation: {0}", rule.PropagationFlags);
                _logger.Info("   Inherited? {0}", rule.IsInherited);
                _logger.Info("");
            }
        }

        /// <summary>
        /// Reads parameter from configuration as string, null if none
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <returns>the parameter value, null if none</returns>
        public string ReadStringParameter(string parameter, string defaultValue = null)
        {
            return (string)Registry.GetValue(FullRegistryKey, parameter, defaultValue);
        }

        /// <summary>
        /// Reads parameter from configuration as string, null if none
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <returns>the parameter value, null if none</returns>
        public List<string> ReadStringListParameter(string parameter, List<string> defaultValue = null)
        {
            string stringList = null;
            if (defaultValue != null)
            {
                if ( defaultValue.Count > 0 )
                    stringList = string.Join(",", defaultValue);
            }
            stringList = (string)Registry.GetValue(FullRegistryKey, parameter, stringList);

            if ( stringList !=null )
            {
                defaultValue = stringList.Split(',').ToList<string>();
            }
            return defaultValue;
        }

        /// <summary>
        /// Writes parameter value into configuration
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <param name="value">the parameter value</param>
        public void WriteStringParameter(string parameter, string value)
        {
            if ((parameter == null) || (value == null)) { return; }
            Registry.SetValue(FullRegistryKey, parameter, value, RegistryValueKind.String);
        }

        /// <summary>
        /// Writes parameter value into configuration
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <param name="value">the parameter value</param>
        public void WriteStringListParameter(string parameter, List<string> list)
        {
            if ((parameter == null) || (list == null)) { return; }

            string value = string.Join(",", list);
            Registry.SetValue(FullRegistryKey, parameter, value, RegistryValueKind.String);
        }

        /// <summary>
        /// Writes parameter value into configuration. Reads it back again
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <param name="value">the parameter value</param>
        public List<string> WriteAndReadStringListParameter(string parameter, List<string> list)
        {
            WriteStringListParameter(parameter, list);
            return ReadStringListParameter(parameter, list);
        }

        /// <summary>
        /// For the given parameter, writes its value into configuration, if value != null. In any case, reads it from configuration.
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the value of the configuration parameter</param>
        /// <returns>the value of the configuration parameter, null if none</returns>
        public string WriteAndReadStringParameter(string parameter, string value, string defaultValue = null)
        {
            if (value != defaultValue)
            {
                WriteStringParameter(parameter, value);
            }
            return ReadStringParameter(parameter);
        }

        /// <summary>
        /// For the given parameter, writes its value into configuration, if value != defaultValue. In any case, reads it from configuration.
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the value of the configuration parameter</param>
        /// <param name="defaultValue">the default value of the configuration parameter</param>
        /// <returns>the value of the configuration parameter, defaultValue if none</returns>
        public int WriteAndReadIntParameter(string parameter, int value, int defaultValue)
        {
            if (value != defaultValue)
                WriteIntParameter(parameter, value);
            return ReadIntParameter(parameter, defaultValue);
        }

        /// <summary>
        /// Tries to read parameter value from configuration. If it does not exist, uses provided value instead, and writes it to configuration
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the default value is parameter does not exist in configuration</param>
        /// <returns>the value of the configuration parameter</returns>
        public string ReadOrWriteStringParameter(string parameter, string value)
        {
            string myValue = ReadStringParameter(parameter);
            if (myValue == null)
            {
                WriteStringParameter(parameter, value);
            }
            return ReadStringParameter(parameter);
        }

        /// <summary>
        /// Read the parameter value from configuration.
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the default value is parameter does not exist in configuration</param>
        /// <returns>the value of the configuration parameter</returns>
        public bool ReadBooleanParameter(string parameter, bool value)
        {
            return (ReadIntParameter(parameter, value ? 1 : 0) == 1);
        }

        /// <summary>
        /// Reads Integer parameter from the configuration
        /// </summary>
        /// <param name="parameter"></param>
        /// <param name="defaultValue"></param>
        /// <returns></returns>
        public int ReadIntParameter(string parameter, int defaultValue = 0)
        {
            return (int)Registry.GetValue(FullRegistryKey, parameter, defaultValue);
        }

        /// <summary>
        /// Tries to read parameter value from configuration. If it does not exist, uses provided value instead, and writes it to configuration
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the default value is parameter does not exist in configuration</param>
        /// <returns>the value of the configuration parameter</returns>
        public int ReadOrWriteIntParameter(string parameter, int value)
        {
            int myValue = ReadIntParameter(parameter, 0);
            if (myValue == 0)
            {
                WriteIntParameter(parameter, value);
            }
            return ReadIntParameter(parameter);
        }

        /// <summary>
        /// Writes integer parameter into configuration
        /// </summary>
        /// <param name="parameter"></param>
        /// <param name="value"></param>
        public void WriteIntParameter(string parameter, int value)
        {
            if (parameter == null) { return; }
            Registry.SetValue(FullRegistryKey, parameter, value, RegistryValueKind.DWord);
        }

        /// <summary>
        /// Aims at handling flags with configuration parameter. Once a flag has been set to true, it's written forever in the configuration
        /// </summary>
        /// <param name="parameter">the flag</param>
        /// <param name="value">the flag's value</param>
        /// <returns>the flag's value</returns>
        public bool WriteAndReadBooleanParameter(string parameter, bool value)
        {
            if (value)
            {
                WriteIntParameter(parameter, 1);
            }
            return (ReadIntParameter(parameter, 0) == 1);
        }

        /// <summary>
        /// Write the Boolean to the registry
        /// </summary>
        /// <param name="parameter">The registry value name, certificate configuration property name</param>
        /// <param name="value">Its value</param>
        /// <returns>The properties value in registry</returns>
        public bool WriteBooleanParameter(string parameter, bool boolValue)
        {
            int value = boolValue ? 1 : 0;
            WriteIntParameter(parameter, value);
            return ReadBooleanParameter(parameter, false);
        }

        /// <summary>
        /// Deletes parameter from configuration
        /// </summary>
        /// <param name="parameter"></param>
        public void DeleteParameter(string parameter)
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey(HKLMRegistryKey, true);
            if (key != null)
            {
                key.DeleteValue(parameter);
            }
        }

        /// <summary>
        /// Is there a configuration parameter starting with given key?
        /// </summary>
        /// <param name="startsWith">the parameter to look for</param>
        public bool IsThereConfigParam(string startsWith)
        {
            foreach (string key in Registry.LocalMachine.OpenSubKey(HKLMRegistryKey).GetValueNames())
            {
                if (key.StartsWith(startsWith,StringComparison.InvariantCultureIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Deletes all WinCertes parameters from configuration
        /// </summary>
        public void DeleteAllParameters()
        {
            try
            {
                //
                // HKLM WinCertes key is for Administrative access only.
                // Manage access rights by using parent permissions from HKLM\Software and remove user permissions.
                //
                _logger.Info("Deleting Registry Key HKLM\\{0}", HKLMRegistryKey);
                RegistryKey keySoftware = Registry.LocalMachine.OpenSubKey(HKLMCertificateParent, true);
                keySoftware.DeleteSubKeyTree(CertificateStore, false);
            }
            catch (Exception e)
            {
                _logger.Warn(e, $"Warning: Could not open/create registry subkey: {e.Message}. We'll try to continue anyway.");
            }
        }
    }
}
