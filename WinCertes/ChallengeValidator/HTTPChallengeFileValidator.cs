using System.IO;

namespace WinCertes.ChallengeValidator
{
    /// <summary>
    /// HTTP Challenge Validator using only filesystem. An existing web server e.g. IIS is needed on the local computer.
    /// </summary>
    class HTTPChallengeFileValidator : IHTTPChallengeValidator
    {
        string _challengeVerifyPath = "";

        /// <summary>
        /// Class constructor
        /// </summary>
        /// <param name="challengeVerifyPath">The root path for the challenge verification. Usually the root directory of the web server.</param>
        public HTTPChallengeFileValidator(string challengeVerifyPath)
        {
            _challengeVerifyPath = challengeVerifyPath;
            // First we create necessary directories
            System.IO.Directory.CreateDirectory($"{_challengeVerifyPath}\\.well-known");
            System.IO.Directory.CreateDirectory($"{_challengeVerifyPath}\\.well-known\\acme-challenge");
        }

        /// <summary>
        /// <see cref="IHTTPChallengeValidator.PrepareChallengeForValidation(string, string)"/>
        /// </summary>
        /// <param name="token"></param>
        /// <param name="keyAuthz"></param>
        public void PrepareChallengeForValidation(string token, string keyAuthz)
        {
            // And we create the token validation file for the challenge
            File.WriteAllText($"{_challengeVerifyPath}\\.well-known\\acme-challenge\\{token}", keyAuthz);
        }

        /// <summary>
        /// <see cref="IHTTPChallengeValidator.CleanupChallengeAfterValidation(string)"/>
        /// </summary>
        /// <param name="token"></param>
        public void CleanupChallengeAfterValidation(string token)
        {
            // Finally we delete file that we needed
            File.Delete($"{_challengeVerifyPath}\\.well-known\\acme-challenge\\{token}");
        }

        public void EndAllChallengeValidations()
        {
            // Finally we delete all directories that we needed
            System.IO.Directory.Delete($"{_challengeVerifyPath}\\.well-known\\acme-challenge");
            System.IO.Directory.Delete($"{_challengeVerifyPath}\\.well-known");
        }
    }
}
