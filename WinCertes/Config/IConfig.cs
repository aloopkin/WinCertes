﻿using System.Collections.Generic;

namespace WinCertes
{
    /// <summary>
    /// Interface to Configuration Engine
    /// </summary>
    interface IConfig
    {
        /// <summary>
        /// Deletes parameter from configuration
        /// </summary>
        /// <param name="parameter"></param>
        void DeleteParameter(string parameter);

        /// <summary>
        /// Reads Integer parameter from the configuration
        /// </summary>
        /// <param name="parameter"></param>
        /// <param name="defaultValue"></param>
        /// <returns></returns>
        int ReadIntParameter(string parameter, int defaultValue = 0);

        /// <summary>
        /// Reads parameter from configuration as string, null if none
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <returns>the parameter value, null if none</returns>
        string ReadStringParameter(string parameter, string defaultValue = null);

        /// <summary>
        /// Reads parameter from configuration as string, null if none
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <returns>the parameter value, null if none</returns>
        List<string> ReadStringListParameter(string parameter, List<string> defaultValue = null);

        /// <summary>
        /// Read the given boolean parameter from the Registry
        /// </summary>
        /// <param name="parameter">Name of the configuration parameter</param>
        /// <param name="defaultValue">Return value if parameter does not exist</param>
        /// <returns>Boolean parameter value</returns>
        bool ReadBooleanParameter(string parameter, bool defaultValue);

        /// <summary>
        /// Tries to read parameter value from configuration. If it does not exist, uses provided value instead, and writes it to configuration
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the default value is parameter does not exist in configuration</param>
        /// <returns>the value of the configuration parameter</returns>
        int ReadOrWriteIntParameter(string parameter, int value);

        /// <summary>
        /// For the given parameter, writes its value into configuration, if value != defaultValue. In any case, reads it from configuration.
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the value of the configuration parameter</param>
        /// <param name="defaultValue">the default value of the configuration parameter</param>
        /// <returns>the value of the configuration parameter, defaultValue if none</returns>
        int WriteAndReadIntParameter(string parameter, int value, int defaultValue);

        /// <summary>
        /// Tries to read parameter value from configuration. If it does not exist, uses provided value instead, and writes it to configuration
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the default value is parameter does not exist in configuration</param>
        /// <returns>the value of the configuration parameter</returns>
        string ReadOrWriteStringParameter(string parameter, string value);

        /// <summary>
        /// Aims at handling flags with configuration parameter. Once a flag has been set to true, it's written forever in the configuration
        /// </summary>
        /// <param name="parameter">the flag</param>
        /// <param name="value">the flag's value</param>
        /// <returns>the flag's value</returns>
        bool WriteAndReadBooleanParameter(string parameter, bool value);

        /// <summary>
        /// For the given parameter, writes its value into configuration, if value != null. In any case, reads it from configuration.
        /// </summary>
        /// <param name="parameter">the configuration parameter to manage</param>
        /// <param name="value">the value of the configuration parameter</param>
        /// <returns>the value of the configuration parameter, null if none</returns>
        string WriteAndReadStringParameter(string parameter, string value, string defaultValue = null);

        /// <summary>
        /// Writes parameter values into configuration, if value != null and reads it back again.
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <param name="value">the list of parameter values</param>
        List<string> WriteAndReadStringListParameter(string parameter, List<string> list);

        /// <summary>
        /// Writes integer parameter into configuration
        /// </summary>
        /// <param name="parameter"></param>
        /// <param name="value"></param>
        void WriteIntParameter(string parameter, int value);

        /// <summary>
        /// Writes parameter value into configuration
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <param name="value">the parameter value</param>
        void WriteStringParameter(string parameter, string value);

        /// <summary>
        /// Writes parameter value into configuration
        /// </summary>
        /// <param name="parameter">the parameter to manage</param>
        /// <param name="value">the parameter values</param>
        void WriteStringListParameter(string parameter, List<string> list);

        /// <summary>
        /// Is there a configuration parameter starting with given key?
        /// </summary>
        /// <param name="startsWith">the parameter to look for</param>
        bool IsThereConfigParam(string startsWith);

        /// <summary>
        /// Deletes all WinCertes parameters from configuration
        /// </summary>
        void DeleteAllParameters();
    }
}