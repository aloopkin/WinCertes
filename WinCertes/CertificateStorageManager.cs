using NLog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace WinCertes
{
    class CertificateStorageManager
    {
        private static readonly ILogger logger = LogManager.GetLogger("WinCertes.CertificateStorageManager");

        public AuthenticatedPFX authenticatedPFX { get; set; }
        public X509Certificate2 certificate { get; set; }

        /// <summary>
        /// Class constructor
        /// </summary>
        /// <param name="authenticatedPFX"></param>
        public CertificateStorageManager(AuthenticatedPFX authenticatedPFX)
        {
            this.authenticatedPFX = authenticatedPFX;
            certificate = null;
        }

        /// <summary>
        /// Process PFX to extract its certificate/key into Windows objects
        /// </summary>
        /// <param name="persist">should the extracted key/cert be persisted?</param>
       public void ProcessPFX(bool persist)
        {
            try
            {
                X509KeyStorageFlags flags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet;
                if (!persist) { flags = X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.Exportable; }
                certificate = new X509Certificate2(authenticatedPFX.PfxFullPath, authenticatedPFX.PfxPassword, flags);
            }
            catch (Exception e)
            {
                logger.Error($"Impossible to extract certificate from PFX: {e.Message}");
            }
        }

        /// <summary>
        /// Imports the member certificate into default windows store. ProcessPFX must be called before this method.
        /// </summary>
        public void ImportCertificateIntoDefaultCSP()
        {
            if (certificate == null)
            {
                logger.Error("No certificate to import.");
                return;
            }
            try
            {
                X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                store.Add(certificate);
                store.Close();
            }
            catch (Exception e)
            {
                logger.Error($"Impossible to import certificate into Default CSP: {e.Message}");
            }
        }

        /// <summary>
        /// Imports PFX into specified CSP/KSP
        /// </summary>
        /// <param name="pfxFullPath"></param>
        /// <param name="pfxPassword"></param>
        /// <param name="KSP"></param>
        public void ImportPFXIntoKSP(string KSP)
        {
            try
            {
                Process process = new Process();
                process.StartInfo.FileName = @"c:\Windows\System32\certutil.exe";
                process.StartInfo.Arguments = $"-importPFX -p {authenticatedPFX.PfxPassword} -csp \"{KSP}\" -f My \"{authenticatedPFX.PfxFullPath}\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                string output = "";
                while (!process.StandardOutput.EndOfStream)
                {
                    output += process.StandardOutput.ReadLine() + "\n";
                }
                process.WaitForExit();
                logger.Debug(output);
                if (output.Contains("FAILED"))
                {
                    logger.Error($"Impossible to import certificate into KSP {KSP}: {output}");
                }
                else
                {
                    logger.Info($"Successfully imported certificate into KSP {KSP}");
                }
            }
            catch (Exception e)
            {
                logger.Error($"Impossible to import certificate into KSP {KSP}: {e.Message}");
            }
        }
    }
}
