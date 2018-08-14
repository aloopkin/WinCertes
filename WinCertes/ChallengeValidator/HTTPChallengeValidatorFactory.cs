using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinCertes.ChallengeValidator
{
    public class HTTPChallengeValidatorFactory
    {
        /// <summary>
        /// Builds the HTTP Challenge Validator. It will also initialise them.
        /// </summary>
        /// <param name="standalone">true if we use the built-in webserver, false otherwise</param>
        /// <param name="webRoot">the full path to the web server root, when not using built-in</param>
        /// <returns>the HTTP challenge Validator</returns>
        public static IHTTPChallengeValidator GetHTTPChallengeValidator(bool standalone, string webRoot = null)
        {
            IHTTPChallengeValidator challengeValidator = null;
            if (standalone) {
                challengeValidator = new HTTPChallengeWebServerValidator();
            } else if (webRoot != null) {
                challengeValidator = new HTTPChallengeFileValidator(webRoot);
            }
            return challengeValidator;
        }
    }
}
