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
                if (!CheckAvailableServerPort(httpPort))
                {
                    Program._logger.Warn("HTTP Standalone activation selected, but port {0} was not available. No HTTP session established", httpPort);
                    return null;
                }
                challengeValidator = new HTTPChallengeWebServerValidator(httpPort);
                if (challengeValidator != null) Program._logger.Info("HTTP Challenge WebServer Validator established, listening on Port({0})", httpPort);
            }
            else if (webRoot != null)
            {
                challengeValidator = new HTTPChallengeFileValidator(webRoot);
                if (challengeValidator != null) Program._logger.Info("HTTP Challenge File Validator established");
            }
            else
            {
                Program._logger.Warn("HTTP Web Server Root path was not specified");
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
