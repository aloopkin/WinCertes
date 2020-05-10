﻿using Microsoft.Web.Administration;
using NLog;
using NLog.Config;
using NLog.Targets;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using TS = Microsoft.Win32.TaskScheduler;

namespace WinCertes
{
    /// <summary>
    /// Convenience class to store PFX and its password together
    /// </summary>
    public class AuthenticatedPFX
    {
        /// <summary>
        /// Constructor for the class
        /// </summary>
        /// <param name="pfxFullPath"></param>
        /// <param name="pfxPassword"></param>
        public AuthenticatedPFX(string pfxFullPath, string pfxPassword)
        {
            PfxFullPath = pfxFullPath;
            PfxPassword = pfxPassword;
        }

        /// <summary>
        /// Full path to the pfx, including the PFX
        /// </summary>
        public string PfxFullPath { get; set; }

        /// <summary>
        /// PFX password
        /// </summary>
        public string PfxPassword { get; set; }
    }

    /// <summary>
    /// This class is a catalog of static methods to be used for various purposes within WinCertes
    /// </summary>
    public class Utils
    {
        private static readonly ILogger logger = LogManager.GetLogger("WinCertes.Utils");

        /// <summary>
        /// Executes powershell script scriptFile
        /// </summary>
        /// <param name="scriptFile"></param>
        /// <param name="pfx"></param>
        /// <param name="pfxPassword"></param>
        /// <returns></returns>
        public static bool ExecutePowerShell(string scriptFile, AuthenticatedPFX pfx)
        {
            if (scriptFile == null) return false;
            try
            {
                // First let's create the execution runspace
                RunspaceConfiguration runspaceConfiguration = RunspaceConfiguration.Create();
                Runspace runspace = RunspaceFactory.CreateRunspace(runspaceConfiguration);
                runspace.Open();

                // Now we create the pipeline
                Pipeline pipeline = runspace.CreatePipeline();

                // We create the script to execute with its arguments as a Command
                System.Management.Automation.Runspaces.Command myCommand = new System.Management.Automation.Runspaces.Command(scriptFile);
                CommandParameter pfxParam = new CommandParameter("pfx", pfx.PfxFullPath);
                myCommand.Parameters.Add(pfxParam);
                CommandParameter pfxPassParam = new CommandParameter("pfxPassword", pfx.PfxPassword);
                myCommand.Parameters.Add(pfxPassParam);

                // add the created Command to the pipeline
                pipeline.Commands.Add(myCommand);

                // and we invoke it
                var results = pipeline.Invoke();
                logger.Info($"Executed script {scriptFile}.");
                return true;
            }
            catch (Exception e)
            {
                logger.Error($"Could not execute {scriptFile}: {e.Message}");
                return false;
            }
        }

        /// <summary>
        /// Binds the specified certificate located in "MY" store to the specified IIS site on the local machine
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="siteName"></param>
        /// <returns>true in case of success, false otherwise</returns>
        public static bool BindCertificateForIISSite(X509Certificate2 certificate, string siteName)
        {
            if (siteName == null) return false;
            try
            {
                bool foundBinding = false;
                ServerManager serverMgr = new ServerManager();
                Site site = serverMgr.Sites[siteName];
                if (site == null)
                {
                    logger.Error($"Could not find IIS site {siteName}");
                    return false;
                }
                foreach (Binding binding in site.Bindings)
                {
                    if (binding.Protocol == "https")
                    {
                        binding.CertificateHash = certificate.GetCertHash();
                        binding.CertificateStoreName = "MY";
                        foundBinding = true;
                    }
                }

                if (!foundBinding)
                {
                    Binding binding = site.Bindings.Add("*:443:", certificate.GetCertHash(), "MY");
                    binding.Protocol = "https";
                }
 
                site.ApplicationDefaults.EnabledProtocols = "http,https";
                serverMgr.CommitChanges();
                return true;
            }
            catch (Exception e)
            {
                logger.Error(e,$"Could not bind certificate to site {siteName}: {e.Message}");
                return false;
            }
        }

        /// <summary>
        /// Tells whether logged in user is admin or not
        /// </summary>
        /// <returns>true if admin, false otherwise</returns>
        public static bool IsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// Attempt elevation if nto running as administrator
        /// </summary>
        public static void AdminRelauncher()
        {
            if (!IsAdministrator())
            {
                ProcessStartInfo proc = new ProcessStartInfo();
                proc.UseShellExecute = true;
                proc.WorkingDirectory = Environment.CurrentDirectory;
                proc.FileName = Assembly.GetEntryAssembly().CodeBase;

                proc.Verb = "runas";

                try
                {
                    Process.Start(proc);
                }
                catch (Exception ex)
                {
                    Program._logger.Info("This program must be run as an administrator! \n\n" + ex.ToString());
                }
                System.Environment.Exit(-1);
            }
        }
        /// <summary>
        /// Configures the console logger
        /// </summary>
        /// <param name="logPath">the path to the directory where to store the log files</param>
        public static void ConfigureLogger(string logPath, string[] args)
        {
            if (logPath == null)
                logPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + "\\WinCertes";

            var config = new LoggingConfiguration();
            LogLevel level = LogLevel.Info;
            if (args != null) foreach (var arg in args) if (arg.ToString().IndexOf("debug", StringComparison.InvariantCultureIgnoreCase) > 0) level = LogLevel.Debug;
#if DEBUG
            config.LoggingRules.Add(new LoggingRule("*", level, new ColoredConsoleTarget { Name = "WinCertes Console", Layout = "[DEBUG] ${message}${onexception:${newline}${exception:format=tostring}}" }));
#else
            config.LoggingRules.Add(new LoggingRule("*", level, new ColoredConsoleTarget { Name = "WinCertes Console", Layout = "${message}" }));
#endif

            config.LoggingRules.Add(
                new LoggingRule("*", level, new FileTarget
                {
                    Name = "WinCertes",
                    FileName = logPath + "\\wincertes.log",
                    ArchiveAboveSize = 500000,
                    ArchiveFileName = logPath + "\\wincertes.old.log",
                    MaxArchiveFiles = 4,
                    ArchiveOldFileOnStartup = true,
                    Layout = "${longdate}|${level:uppercase=true}| ${message}${onexception:${newline}${exception:format=tostring}}"
                }));

            LogManager.Configuration = config;
        }

        /// <summary>
        /// Change the log level for NLog after the command line parameters have been read
        /// </summary>
        /// <param name="logLevel">The new log level</param>
        /// <param name="regex">Regular expression for Log target name. e.g. "*"</param>
        public static void SetLogLevel(LogLevel logLevel, string regex = "wincertes*")
        {
            IList<NLog.Config.LoggingRule> rules = LogManager.Configuration.LoggingRules;
            Regex validator = new Regex(regex, RegexOptions.IgnoreCase);
            //foreach (var rule in rules.Where(x => validator.IsMatch(x.Targets[0].Name)))
            foreach (var rule in rules)
            {
                if (validator.IsMatch(rule.Targets[0].Name))
                {
                    if (!rule.IsLoggingEnabledForLevel(logLevel))
                    {
                        rule.EnableLoggingForLevel(logLevel);
                    }
                }
            }
        }

        /// <summary>
        /// Creates the windows scheduled task
        /// </summary>
        /// <param name="domains"></param>
        /// <param name="taskName"></param>
        public static void CreateScheduledTask(string taskName, List<string> domains, bool extra)
        {
            if (taskName == null) return;
            try
            {
                using (TS.TaskService ts = new TS.TaskService())
                {
                    // Create a new task definition and assign properties
                    TS.TaskDefinition td = ts.NewTask();
                    td.RegistrationInfo.Description = "Manages certificate using ACME";

                    // We need to run as SYSTEM user
                    td.Principal.UserId = @"NT AUTHORITY\SYSTEM";

                    // Create a trigger that will fire the task at this time every other day
                    td.Triggers.Add(new TS.DailyTrigger { DaysInterval = 2 });
                    String extraOpt = "";

                    if (extra)
                        extraOpt = "--extra ";
                    // Create an action that will launch Notepad whenever the trigger fires
                    td.Actions.Add(new TS.ExecAction("WinCertes.exe", extraOpt + "-d " + String.Join(" -d ", domains), Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)));

                    // Register the task in the root folder
                    ts.RootFolder.RegisterTaskDefinition($"WinCertes - {taskName}", td);
                }
                logger.Info($"Scheduled Task \"WinCertes - {taskName}\" created successfully");
            }
            catch (Exception e)
            {
                logger.Error("Unable to create Scheduled Task" + e.Message);
            }
        }

        public static bool IsScheduledTaskCreated()
        {
            try
            {
                using (TS.TaskService ts = new TS.TaskService())
                {
                    foreach (TS.Task t in ts.RootFolder.Tasks)
                    {
                        if (t.Name.StartsWith("WinCertes", StringComparison.InvariantCultureIgnoreCase))
                            return true;
                    }
                }
                return false;
            }
            catch (Exception e)
            {
                logger.Error("Unable to read Scheduled Task status" + e.Message);
                return false;
            }
        }

        public static void DeleteScheduledTasks()
        {
            try
            {
                using (TS.TaskService ts = new TS.TaskService())
                {
                    foreach (TS.Task t in ts.RootFolder.Tasks)
                    {
                        if (t.Name.StartsWith("WinCertes", StringComparison.InvariantCultureIgnoreCase))
                            ts.RootFolder.DeleteTask(t.Name, false);
                    }
                }
            }
            catch (Exception e)
            {
                logger.Error("Unable to read Scheduled Task status" + e.Message);
            }
        }

        /// <summary>
        /// Small, utilitary function, to compute an MD5 Hash. Yes, MD5 isn't wonderful, but we don't use it for high class crypto.
        /// </summary>
        /// <param name="md5Hash"></param>
        /// <param name="input"></param>
        /// <returns></returns>
        private static string GetMD5Hash(MD5 md5Hash, string input)
        {
            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
            // Create a new Stringbuilder to collect the bytes and create a string.
            StringBuilder sBuilder = new StringBuilder();
            // Loop through each byte of the hashed data and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }
            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        /// <summary>
        /// Convenience function to compute a digital identifier from the list of domains
        /// </summary>
        /// <param name="domains">the list of domains</param>
        /// <returns>the identifier</returns>
        public static string DomainsToHostId(List<string> domains)
        {
            List<string> wDomains = new List<string>(domains);
            wDomains.Sort();
            string domainList = String.Join("-", wDomains);
            return "_" + GetMD5Hash(MD5.Create(), domainList).Substring(0, 16).ToLower();
        }

        /// <summary>
        /// Convenience method to compute a humain readable name for a list of domains
        /// </summary>
        /// <param name="domains">the list of domains</param>
        /// <returns>the human readable name</returns>
        public static string DomainsToFriendlyName(List<string> domains)
        {
            if (domains.Count == 0)
            {
                return "WinCertes";
            }
            List<string> wDomains = new List<string>(domains);
            wDomains.Sort();
            wDomains.Sort();
            string friendly = wDomains[0].Replace(@"*", "").Replace("-", "").Replace(":", "").Replace(".", "");
            friendly += "0000000000000000";
            friendly = friendly.Substring(0, 16);
            Program._logger.Info("Friendly name: {0}", friendly);
            return friendly;
        }

        /// <summary>
        /// Retrieves a certificate from machine store, given its serial number
        /// </summary>
        /// <param name="serial">the serial number of the certificate to retrieve</param>
        /// <returns>the certificate, or null if not found</returns>
        public static X509Certificate2 GetCertificateBySerial(string serial)
        {
            try
            {
                X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection collection = store.Certificates.Find(X509FindType.FindBySerialNumber, serial, false);
                store.Close();
                if (collection.Count == 0)
                {
                    return null;
                }
                else
                {
                    X509Certificate2 cert = collection[0];
                    return cert;
                }
            }
            catch (Exception e)
            {
                logger.Error($"Could not retrieve certificate from store: {e.Message}");
                return null;
            }
        }
    }
}
