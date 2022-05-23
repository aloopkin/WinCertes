using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading.Tasks;

namespace WinCertes.ChallengeValidator
{
    class DNSChallengePowerShellValidator : IDNSChallengeValidator
    {
        private static readonly ILogger logger = LogManager.GetLogger("WinCertes.ChallengeValidator.DNSChallengePowerShellValidator");

        private IConfig _config;

        public DNSChallengePowerShellValidator(IConfig config)
        {
            _config = config;
        }

        public bool PrepareChallengeForValidation(string dnsKeyName, string dnsKeyValue)
        {
            var scriptFile = _config.ReadStringParameter("DNSScriptFile");
            if (scriptFile == null)
                throw new Exception("No DNSScriptFile was configured whil calling DNS PowerShell Validator plug-in");
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
                CommandParameter dnsKeyNameParam = new CommandParameter("dnsKeyName",dnsKeyValue);
                myCommand.Parameters.Add(dnsKeyNameParam);
                CommandParameter dnsKeyValueParam = new CommandParameter("dnsKeyValue", dnsKeyValue);
                myCommand.Parameters.Add(dnsKeyValueParam);

                // add the created Command to the pipeline
                pipeline.Commands.Add(myCommand);

                // and we invoke it
                var results = pipeline.Invoke();
                logger.Info($"Executed DNS Challenge Script {scriptFile}.");
                return true;
            }
            catch (Exception e)
            {
                logger.Error($"Could not execute {scriptFile}: {e.Message}");
                return false;
            }
        }
    }
}
