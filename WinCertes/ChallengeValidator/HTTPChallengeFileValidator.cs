using NLog;
using System;
using System.IO;

namespace WinCertes.ChallengeValidator
{
    /// <summary>
    /// HTTP Challenge Validator using only filesystem. An existing web server e.g. IIS is needed on the local computer.
    /// </summary>
    class HTTPChallengeFileValidator : IHTTPChallengeValidator
    {
        private static readonly ILogger logger = LogManager.GetLogger("WinCertes.ChallengeValidator.HTTPChallengeFileValidator");

        string _challengeVerifyPath = "";

        /// <summary>
        /// Class constructor
        /// </summary>
        /// <param name="challengeVerifyPath">The root path for the challenge verification. Usually the root directory of the web server.</param>
        public HTTPChallengeFileValidator(string challengeVerifyPath)
        {
            _challengeVerifyPath = challengeVerifyPath;
            string webConfig = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n<system.webServer>\n<staticContent>"
                 + "<mimeMap fileExtension=\".*\" mimeType=\"application/octet-stream\"/>\n</staticContent>\n</system.webServer>\n</configuration>";
            try {
                // First we create necessary directories
                System.IO.Directory.CreateDirectory($"{_challengeVerifyPath}\\.well-known");
                System.IO.Directory.CreateDirectory($"{_challengeVerifyPath}\\.well-known\\acme-challenge");
                File.WriteAllText($"{_challengeVerifyPath}\\.well-known\\acme-challenge\\web.config", webConfig);
            } catch (Exception e) {
                logger.Warn($"Could not create Directories for HTTP validation: {e.Message}");
            }
        }

        /// <summary>
        /// <see cref="IHTTPChallengeValidator.PrepareChallengeForValidation(string, string)"/>
        /// </summary>
        /// <param name="token"></param>
        /// <param name="keyAuthz"></param>
        public bool PrepareChallengeForValidation(string token, string keyAuthz)
        {
            try {
                // And we create the token validation file for the challenge
                File.WriteAllText($"{_challengeVerifyPath}\\.well-known\\acme-challenge\\{token}", keyAuthz);
                return true;
            } catch (Exception e) {
                logger.Error($"Could not write challenge file: {e.Message}");
                return false;
            }
        }

        /// <summary>
        /// <see cref="IHTTPChallengeValidator.CleanupChallengeAfterValidation(string)"/>
        /// </summary>
        /// <param name="token"></param>
        public void CleanupChallengeAfterValidation(string token)
        {
            try {
                // Finally we delete file that we needed
                File.Delete($"{_challengeVerifyPath}\\.well-known\\acme-challenge\\{token}");
            } catch (Exception e) {
                logger.Error($"Could not delete challenge file: {e.Message}");
            }
        }

        public void EndAllChallengeValidations()
        {
            try {
                File.Delete($"{_challengeVerifyPath}\\.well-known\\acme-challenge\\web.config");
                // Finally we delete all directories that we needed
                System.IO.Directory.Delete($"{_challengeVerifyPath}\\.well-known\\acme-challenge");
                System.IO.Directory.Delete($"{_challengeVerifyPath}\\.well-known");
            } catch (Exception e) {
                logger.Warn($"Could not delete challenge file directory: {e.Message}");
            }

        }
    }
}
