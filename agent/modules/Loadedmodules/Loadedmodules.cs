using System;
using System.Linq;
using System.Diagnostics;
using Microsoft.Diagnostics.Runtime;

// Compiling instructions:
// Add the Microsoft.Diagnostics.Runtime Nuget module ...
// Uncheck "Prefer 32-bit" in the project properties
// Compile as Release/AnyCPU
// Merge required modules into the assembly using ILMerge with the command below:

// .\ILMerge.exe /out:LoadedModules.exe ..\..\..\..\..\LoadedModules\LoadedModules\bin\Release\LoadedModules.exe C:\Users\localadmin\source\repos\LoadedModules\LoadedModules\bin\Release\Microsoft.Diagnostics.Runtime.dll C:\Users\localadmin\source\repos\LoadedModules\LoadedModules\bin\Release\System.Collections.Immutable.dll C:\Users\localadmin\source\repos\LoadedModules\LoadedModules\bin\Release\System.Memory.dll C:\Users\localadmin\source\repos\LoadedModules\LoadedModules\bin\Release\System.Runtime.CompilerServices.Unsafe.dll C:\Users\localadmin\source\repos\LoadedModules\LoadedModules\bin\Release\System.Buffers.dll /closed

// You can actually use LoadedModules.exe to find which .NET assemblies you need to include into LoadedModules.exe itself with ILMerge


// Lists loaded managed and unmanaged modules in the current process (default) or another process (specify with PID or process name)
namespace LoadedModules
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Process proc = null;
            if (args.Length == 0) // current process
            {
                proc = Process.GetCurrentProcess();
            }
            else if (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("LoadedModules               -- shows loaded modules for the current process");
                Console.WriteLine("LoadedModules <pid>         -- shows loaded modules for the specified process");
                Console.WriteLine("LoadedModules <processname> -- shows loaded modules for the specified process");
            }
            else
            {
                int.TryParse(args[0], out int pid);
                if (pid != 0)
                {

                    try
                    {
                        proc = Process.GetProcessById(pid);
                    }
                    catch (ArgumentException)
                    {
                        Console.WriteLine("[!] Error: No processes running with PID: " + args[0]);
                        return;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Error: unhandled exception getting handle on PID: " + args[0]);
                        Console.WriteLine(e);
                        return;
                    }

                }
                else // process by name
                {
                    string name = args[0];
                    if (args[0].EndsWith(".exe"))
                    {
                        name = String.Concat(args[0].Reverse().Skip(4).Reverse()); // just wanna remove the .exe at the end :(
                    }
                    Process[] processes = Process.GetProcessesByName(name);
                    if (processes.Length != 1)
                    {
                        Console.WriteLine("[!] Error: Either process is not running or 2 or more processes exist with name: " + args[0]);
                        Console.WriteLine("[!] Try running with a PID instead");
                        return;
                    }
                }
            }
            foreach (var module in proc.Modules)
            {
                Console.WriteLine(string.Format("Unmanaged Module: {0}", module.ToString().Split(' ')[1]));
            }
            Console.WriteLine();

            DataTarget dt = null;
            try
            {
                dt = DataTarget.AttachToProcess(proc.Id, false);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Could not attach to remote process: {0}", e.Message);
                return;
            }

            var assemblies = dt
                  .ClrVersions
                  .Select(dtClrVersion => dtClrVersion.CreateRuntime())
                  .SelectMany(runtime => runtime.AppDomains.SelectMany(runtimeAppDomain => runtimeAppDomain.Modules))
                  .Select(clrModule => clrModule.AssemblyName)
                  .Distinct()
                  .ToList();
            foreach (string assembly in assemblies)
            {
                Console.WriteLine("Managed Assembly: {0}", assembly);
            }
        }
    }
}
