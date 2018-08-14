namespace WinCertes.ChallengeValidator
{
    /// <summary>
    /// Interface for HTTP Challenge Validation
    /// </summary>
    public interface IHTTPChallengeValidator
    {
        /// <summary>
        /// Prepare for challenge validation, by setting up everything that we need so that the ACME Service is able to validate the challenge
        /// </summary>
        /// <param name="token">challenge token</param>
        /// <param name="keyAuthz">challenge token value (authorization key)</param>
        void PrepareChallengeForValidation(string token, string keyAuthz);

        /// <summary>
        /// Cleanup everything, once challenge validation has been performed by ACME Service.
        /// </summary>
        /// <param name="token">challenge token</param>
        void CleanupChallengeAfterValidation(string token);

        /// <summary>
        /// Once all challenge validations have been performed, call this to perform any further required cleanup
        /// </summary>
        void EndAllChallengeValidations();
    }
}
