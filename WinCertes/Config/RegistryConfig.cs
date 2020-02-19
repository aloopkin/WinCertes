using Microsoft.Win32;
using NLog;
using System;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WinCertes
{
    /// <summary>
    /// Configuration class, managing WinCertes configuration into Windows Registry
    /// </summary>
    class RegistryConfig : IConfig
    {
        private static readonly ILogger _logger = LogManager.GetLogger("WinCertes.WinCertesOptions");

        private static string _registryKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\WinCertes";
        private static string _subKey = @"Software\WinCertes";

        /// <summary>
        /// Class constructor. if extra = false, builds the base config. if extra = true, builds the extra certificate config.
        /// </summary>
        public RegistryConfig(bool extra = false)
        {
            try
            {
                if (Registry.LocalMachine.OpenSubKey("SOFTWARE").OpenSubKey("WinCertes") == null)
                {
                    Registry.LocalMachine.OpenSubKey("SOFTWARE",true).CreateSubKey("WinCertes",true);
                }
                if (extra)
                {
                    if (Registry.LocalMachine.OpenSubKey("SOFTWARE").OpenSubKey("WinCertes").OpenSubKey("extra") == null)
                    {
                        _logger.Debug("Creating SubKey 'extra'");
                        Registry.LocalMachine.OpenSubKey("SOFTWARE").OpenSubKey("WinCertes",true).CreateSubKey("extra", true);
                    }
                    _registryKey += @"\extra";
                    _subKey += @"\extra";
                }
                RegistryKey regKey = Registry.LocalMachine.OpenSubKey("SOFTWARE").OpenSubKey("WinCertes", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.FullControl);
                RegistrySecurity regSec = regKey.GetAccessControl(AccessControlSections.All);
                regSec.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
                regSec.SetAccessRuleProtection(true, false);
                regKey.SetAccessControl(regSec);
                RegistryAccessRule adminFull = new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), RegistryRights.FullControl, InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow);
                regSec.AddAccessRule(adminFull);
                adminFull = new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), RegistryRights.FullControl, InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow);
                regSec.AddAccessRule(adminFull);
                regKey.SetAccessControl(regSec);
            }
            catch (Exception e)
            {
                _logger.Warn(e,$"Warning: Could not open/create registry subkey: {e.Message}. We'll try to continue anyway.");
            }
        }

        /// <summary>
        /// Reads parameter from configuration as string, null if none
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <returns>the parameter value, null if none</returns>
        public string ReadStringParameter(string parameter)
        {
            return (string)Registry.GetValue(_registryKey, parameter, null);
        }

        /// <summary>
        /// Writes parameter value into configuration
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <param name="value">the parameter value</param>
        public void WriteStringParameter(string parameter, string value)
        {
            if ((parameter == null) || (value == null)) { return; }
            Registry.SetValue(_registryKey, parameter, value, RegistryValueKind.String);
        }

        /// <summary>
        /// For the given parameter, writes its value into configuration, if value != null. In any case, reads it from configuration.
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the value of the configuration parameter</param>
        /// <returns>the value of the configuration parameter, null if none</returns>
        public string WriteAndReadStringParameter(string parameter, string value)
        {
            if (value != null)
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
        /// Reads Integer parameter from the configuration
        /// </summary>
        /// <param name="parameter"></param>
        /// <param name="defaultValue"></param>
        /// <returns></returns>
        public int ReadIntParameter(string parameter, int defaultValue = 0)
        {
            return (int)Registry.GetValue(_registryKey, parameter, defaultValue);
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
            Registry.SetValue(_registryKey, parameter, value, RegistryValueKind.DWord);
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
        /// Deletes parameter from configuration
        /// </summary>
        /// <param name="parameter"></param>
        public void DeleteParameter(string parameter)
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey(_subKey, true);
            if (key != null)
            {
                key.DeleteValue(parameter);
            }
        }

        /// <summary>
        /// Is there a configuration parameter starting with given key?
        /// </summary>
        /// <param name="startsWith">the parameter to look for</param>
        public bool isThereConfigParam(string startsWith)
        {
            foreach (string key in Registry.LocalMachine.OpenSubKey(_subKey).GetValueNames())
            {
                if (key.StartsWith(startsWith))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Deletes all WinCertes parameters from configuration
        /// </summary>
        public void DeleteAllParameters()
        {
            if (Registry.LocalMachine.OpenSubKey("SOFTWARE").OpenSubKey("WinCertes").OpenSubKey("extra") != null)
            {
                Registry.LocalMachine.OpenSubKey(_subKey,true).DeleteSubKeyTree("extra");
            }
            foreach (string key in Registry.LocalMachine.OpenSubKey(_subKey).GetValueNames())
            {
                DeleteParameter(key);
            }
        }
    }
}
