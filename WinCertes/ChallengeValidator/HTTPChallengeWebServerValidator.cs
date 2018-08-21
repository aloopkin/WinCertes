using NLog;
using System;
using System.Net;
using System.Text;
using System.Threading;

namespace WinCertes.ChallengeValidator
{
    class HTTPChallengeWebServerValidator : IHTTPChallengeValidator
    {
        private static readonly ILogger logger = LogManager.GetLogger("WinCertes.ChallengeValidator.HTTPChallengeWebServerValidator");
        private Thread _serverThread;
        private HttpListener _listener;
        private string _tokenContents;

        private void Listen()
        {
            try {
                _listener = new HttpListener();
                _listener.Prefixes.Add("http://*:80/");
                _listener.Start();
                logger.Debug("Started Listener on port 80");
                while (true) {
                    try {
                        HttpListenerContext context = _listener.GetContext();
                        Process(context);
                    } catch (Exception) {
                        // ignore error, as thread abort will generate one anyway
                    }
                }
            } catch (Exception e) {
                logger.Error($"Could not start to listen on port 80: {e.Message}");
            }
        }

        private void Process(HttpListenerContext context)
        {
            logger.Debug($"Processing the serving of content: {_tokenContents}");
            byte[] buf = Encoding.UTF8.GetBytes(_tokenContents);
            // First the headers
            context.Response.ContentType = "application/octet-stream";
            context.Response.ContentLength64 = buf.Length;
            context.Response.AddHeader("Date", DateTime.Now.ToString("r"));
            context.Response.StatusCode = 200;

            // Then the contents...erm, always the same !
            context.Response.OutputStream.Write(buf, 0, buf.Length);

            // We flush and close
            context.Response.OutputStream.Flush();
            context.Response.OutputStream.Close();
        }

        /// <summary>
        /// Class constructor. Starts the simple web server on port 80.
        /// HTTPChallengeWebServerValidator.Stop() MUST be called after use.
        /// </summary>
        public HTTPChallengeWebServerValidator()
        {
            try {
                _serverThread = new Thread(this.Listen) {
                    IsBackground = true
                };
                _serverThread.Start();
            } catch (Exception e) {
                logger.Warn($"Could not start web server: {e.Message}.");
            }
        }

        /// <summary>
        /// <see cref="IHTTPChallengeValidator.PrepareChallengeForValidation(string, string)"/>
        /// </summary>
        /// <param name="token"></param>
        /// <param name="keyAuthz"></param>
        public bool PrepareChallengeForValidation(string token, string keyAuthz)
        {
            _tokenContents = keyAuthz;
            if (_serverThread != null) return true;
            return false;
        }

        /// <summary>
        /// <see cref="IHTTPChallengeValidator.CleanupChallengeAfterValidation(string)"/>
        /// </summary>
        /// <param name="token"></param>
        public void CleanupChallengeAfterValidation(string token)
        {
            _tokenContents = "";
        }

        /// <summary>
        /// Stops the simple web server
        /// </summary>
        public void EndAllChallengeValidations()
        {
            _serverThread.Abort();
            _listener.Stop();
            logger.Debug("Just stopped the Listener on port 80");
        }
    }
}
