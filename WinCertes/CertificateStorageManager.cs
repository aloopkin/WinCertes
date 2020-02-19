using NLog;
using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace WinCertes
{
    public class CertificateStorageManager
    {
        private static readonly ILogger logger = LogManager.GetLogger("WinCertes.CertificateStorageManager");

        public AuthenticatedPFX AuthenticatedPFX { get; set; }
        public X509Certificate2 Certificate { get; set; }
        private bool DefaultCSP { get; set; }

        /// <summary>
        /// Class constructor
        /// </summary>
        /// <param name="authenticatedPFX">the PFX that we will store</param>
        /// <param name="defaultCSP">do we use the default CSP to store the certificate?</param>
        public CertificateStorageManager(AuthenticatedPFX authenticatedPFX, bool defaultCSP)
        {
            AuthenticatedPFX = authenticatedPFX;
            Certificate = null;
            DefaultCSP = defaultCSP;
        }

        /// <summary>
        /// Process PFX to extract its certificate/key into Windows objects
        /// </summary>
        public void ProcessPFX()
        {
            try {
                // If we use the default CSP, then the key should be persisted as local machine while we parse the certificate
                X509KeyStorageFlags flags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet;
                // else it should be left non-persistent so that it can disappear after treatment
                if (!DefaultCSP) {
                    logger.Debug("Not using default CSP: not importing into store.");
                    flags = X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.Exportable; 
                }
                Certificate = new X509Certificate2(AuthenticatedPFX.PfxFullPath, AuthenticatedPFX.PfxPassword, flags);
            } catch (Exception e) {
                logger.Error($"Impossible to extract certificate from PFX: {e.Message}");
            }
        }

        /// <summary>
        /// Imports the member certificate into default windows store. ProcessPFX must be called before this method.
        /// </summary>
        public void ImportCertificateIntoDefaultCSP()
        {
            if (Certificate == null) { logger.Error("No certificate to import."); return; }
            try {
                X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                store.Add(Certificate);
                store.Close();
                logger.Info($"Stored certificate with DN {Certificate.Subject} into Windows Personal Local Machine store");
                // Now let's try to import the full chain
                try {
                    X509Certificate2Collection certCol = new X509Certificate2Collection();
                    X509KeyStorageFlags flags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet;
                    certCol.Import(AuthenticatedPFX.PfxFullPath, AuthenticatedPFX.PfxPassword, flags);
                    foreach (X509Certificate2 certFile in certCol) {
                        if (certFile.Equals(Certificate)) continue;
                        store = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
                        store.Open(OpenFlags.ReadWrite);
                        store.Add(certFile);
                        store.Close();
                    }
                } catch (Exception) { /* discarded as it's not so important if it fails */ }
            } catch (Exception e) {
                logger.Error(e,$"Impossible to import certificate into Default CSP: {e.Message}");
            }
        }

        /// <summary>
        /// Imports PFX into specified CSP/KSP
        /// </summary>
        /// <param name="KSP">the CSP/KSP name</param>
        public void ImportPFXIntoKSP(string KSP)
        {
            try {
                Process process = new Process();
                process.StartInfo.FileName = @"c:\Windows\System32\certutil.exe";
                process.StartInfo.Arguments = $"-importPFX -p {AuthenticatedPFX.PfxPassword} -csp \"{KSP}\" -f My \"{AuthenticatedPFX.PfxFullPath}\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                string output = "";
                while (!process.StandardOutput.EndOfStream) {
                    output += process.StandardOutput.ReadLine() + "\n";
                }
                process.WaitForExit();
                logger.Debug(output);
                if (output.Contains("FAILED")) {
                    logger.Error($"Impossible to import certificate into KSP {KSP}: {output}");
                } else {
                    logger.Info($"Successfully imported certificate into KSP {KSP}");
                }
            } catch (Exception e) {
                logger.Error($"Impossible to import certificate into KSP {KSP}: {e.Message}");
            }
        }

        /// <summary>
        /// Imports the certificate into the specified CSP, or into default one if csp parameter is null
        /// </summary>
        /// <param name="csp">the name of the csp/ksp to import certificate</param>
        public void ImportCertificateIntoCSP(string csp = null)
        {
            if (csp == null) {
                this.ImportCertificateIntoDefaultCSP();
            } else {
                this.ImportPFXIntoKSP(csp);
            }
        }
    }
}
