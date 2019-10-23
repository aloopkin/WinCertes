using NLog;
using System.Net;
using System.Net.NetworkInformation;

namespace WinCertes.ChallengeValidator
{
    public class HTTPChallengeValidatorFactory
    {
        private static readonly ILogger logger = LogManager.GetLogger("WinCertes.ChallengeValidator.HTTPChallengeValidatorFactory");

        /// <summary>
        /// Builds the HTTP Challenge Validator. It will also initialise them.
        /// </summary>
        /// <param name="standalone">true if we use the built-in webserver, false otherwise</param>
        /// <param name="webRoot">the full path to the web server root, when not using built-in</param>
        /// <returns>the HTTP challenge Validator</returns>
        public static IHTTPChallengeValidator GetHTTPChallengeValidator(bool standalone, int httpPort, string webRoot = null)
        {
            IHTTPChallengeValidator challengeValidator = null;
            if (standalone) {
                if (!CheckAvailableServerPort(httpPort)) return null;
                challengeValidator = new HTTPChallengeWebServerValidator(httpPort);
            } else if (webRoot != null) {
                challengeValidator = new HTTPChallengeFileValidator(webRoot);
            }
            return challengeValidator;
        }

        private static bool CheckAvailableServerPort(int port)
        {
            bool isAvailable = true;
            IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] tcpConnInfoArray = ipGlobalProperties.GetActiveTcpListeners();
            foreach (IPEndPoint endpoint in tcpConnInfoArray) {
                if (endpoint.Port == port) {
                    isAvailable = false;
                    break;
                }
            }
            if (!isAvailable) logger.Error($"Impossible to bind on port {port}. A program is probably already listening on it.");
            return isAvailable;
        }
    }
}
