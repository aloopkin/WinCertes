using Microsoft.Win32;
using System;
using System.CodeDom;
using System.CodeDom.Compiler;
using System.IO;
using WixSharp;


namespace MSIPackaging
{
    class Script
    {

        static public void Main(string[] args)
        {
            var path = "..\\..\\..";
            if (args.Length > 0) { path = args[0]; path = path.Replace(@"\", @"\\"); path = path.Replace("\"", ""); }
            if (path.Contains("MSBUILD")) { return; }
            Console.WriteLine("**** This is the path for building: " + path);
            var project = new Project("WinCertes",
                              new Dir(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\WinCertes",
#if DEBUG
                                  new Files(path + @"\WinCertes\bin\Debug\*.*")
#else
                                  new Files(path + @"\WinCertes\bin\Release\*.*")
#endif
                                  ),
                              new RegValue(RegistryHive.LocalMachine, @"Software\WinCertes", "license", "GPLv3") { Win64 = true },
                              new RemoveRegistryValue(RegistryHive.LocalMachine, @"Software\WinCertes"),
                              new RemoveRegistryKey(RegistryHive.LocalMachine, @"Software\WinCertes"),
                              new EnvironmentVariable("Path", @"[INSTALLDIR]") {
                                  Id = "Path_WinCertes_INSTALLDIR",
                                  Action = EnvVarAction.set,
                                  Part = EnvVarPart.last,
                                  Permanent = false,
                                  System = true
                              }
                              );
            project.GUID = new Guid("bb0a8e11-24a8-4d7e-a7d6-6fc5bd8166d2");
            project.Version = Version.Parse("1.2.0");
            project.LicenceFile = path + @"\MSIPackaging\Resources\gpl-3.0.rtf";
            project.BannerImage = path + @"\MSIPackaging\Resources\banner.png";
            project.BackgroundImage = path + @"\MSIPackaging\Resources\background.png";
            project.Platform = Platform.x64;
            Compiler.BuildMsi(project);
        }
    }
}
