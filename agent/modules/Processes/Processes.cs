using System;
using System.Collections;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;

namespace Processes
{
    public class Program
    {
        [DllImport("kernel32.dll")]
        static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Auto)]
        public static extern IntPtr GetParent(IntPtr hWnd);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int GetProcessId(IntPtr hProcess);

        /// <summary>
        /// A utility class to determine a process parent.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct ParentProcessUtilities
        {
            // These members must match PROCESS_BASIC_INFORMATION
            internal IntPtr Reserved1;
            internal IntPtr PebBaseAddress;
            internal IntPtr Reserved2_0;
            internal IntPtr Reserved2_1;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;

            [DllImport("ntdll.dll")]
            private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);

            /// <summary>
            /// Gets the parent process of the current process.
            /// </summary>
            /// <returns>An instance of the Process class.</returns>
            public static Process GetParentProcess()
            {
                return GetParentProcess(Process.GetCurrentProcess().Handle);
            }

            /// <summary>
            /// Gets the parent process of specified process.
            /// </summary>
            /// <param name="id">The process id.</param>
            /// <returns>An instance of the Process class.</returns>
            public static Process GetParentProcess(int id)
            {
                Process process = Process.GetProcessById(id);
                return GetParentProcess(process.Handle);
            }

            /// <summary>
            /// Gets the parent process of a specified process.
            /// </summary>
            /// <param name="handle">The process handle.</param>
            /// <returns>An instance of the Process class.</returns>
            public static Process GetParentProcess(IntPtr handle)
            {
                ParentProcessUtilities pbi = new ParentProcessUtilities();
                int returnLength;
                int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
                if (status != 0)
                    throw new Win32Exception(status);

                try
                {
                    return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
                }
                catch (ArgumentException)
                {
                    // not found
                    return null;
                }
            }
        }
        private static bool IsWin64Emulator(Process process)
        {
            if ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1)))
            {
                bool retVal;
                return IsWow64Process(process.Handle, out retVal) && retVal;
            }
            return false; // not on 64-bit Windows Emulator
        }
        public static int Ps(string[] args)
        {
            if (args.Length != 0 && (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help"))
            {
                Console.WriteLine("Ps: List all processes or list processes by name");
                Console.WriteLine("Example: ps");
                Console.WriteLine("Example: ps notepad firefox");
                Console.WriteLine("Example: ps poo");
                return 0;
            }

            ManagementScope scope = new System.Management.ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();

            Dictionary<Int32, String> owners = new Dictionary<Int32, String>();
            foreach (ManagementObject managementObject in objectCollection)
            {
                String[] owner = new String[2];
                try
                {
                    managementObject.InvokeMethod("GetOwner", owner);
                }
                catch
                {
                    owner[0] = "X";
                }
                String name = owner[0] != null ? owner[1] + "\\" + owner[0] : "X";
                owners[Convert.ToInt32(managementObject["Handle"])] = name;
            }

            Process[] processes = Process.GetProcesses();
            processes = processes.Where(e => !args.Any() || args.Any(a => e.ProcessName.Contains(a))).ToArray(); //WTF ????
            ArrayList pidList = new ArrayList();
            object[] pids;
            foreach (Process process in processes)
            {
                pidList.Add(process.Id);
            }
            pids = pidList.ToArray();
            Array.Sort(pids);
            List<object> processesList = new List<object>();
            
            foreach (int pid in pids)
            {
                Process process = Process.GetProcessById(0); // fall back option so things don't break
                string process_id = pid.ToString();
                string processName = process.ProcessName;
                try
                {
                    process = Process.GetProcessById(pid);
                }
                catch { }
                string strSessID;
                try
                {
                    uint sessID;
                    ProcessIdToSessionId((uint)pid, out sessID);
                    strSessID = sessID.ToString();
                }
                catch (Exception)
                {
                    strSessID = "X";
                }
                string architecture;
                try
                {
                    architecture = IsWin64Emulator(process) ? "x86" : "x64";
                }
                catch (Exception)
                {
                    architecture = "X";
                }
                string ppidString;
                string userName;
                try
                {
                    if (!owners.TryGetValue(process.Id, out userName))
                    {
                        userName = "X";
                    }
                }
                catch (ArgumentNullException)
                {
                    userName = "X";
                }
                try
                {
                    Process parent = ParentProcessUtilities.GetParentProcess(process.Id);
                    ppidString = parent.Id.ToString();
                }
                catch
                {
                    ppidString = "X";
                }
                processesList.Add(new { process_id, ppidString, architecture, strSessID, userName, processName });
            }
            Console.WriteLine(JsonSerializer.Serialize(processesList));
            return 4; // returnType 4 = processes
        }

        public static int Kill(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("Kill: terminate one or more processes by PID or name");
                Console.WriteLine("Example: kill firefox.exe");
                Console.WriteLine("Example: kill 1337 8484");
                return 0;
            }

            foreach (string arg in args)
            {
                int.TryParse(arg, out int pid);
                if (pid != 0)
                {
                    Process process = null;
                    try
                    {
                        process = Process.GetProcessById(pid);
                    }
                    catch (ArgumentException)
                    {
                        Console.WriteLine("[!] Error: No processes running with PID: " + arg);
                        continue;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Error: unhandled exception getting handle on PID: " + arg);
                        Console.WriteLine(e);
                        continue;
                    }

                    try
                    {
                        process.Kill();
                        Console.WriteLine("[*] Killed process " + process.Id + " (" + process.ProcessName + ")");
                    }
                    catch (Win32Exception)
                    {
                        Console.WriteLine("Error: could not kill process by process ID: " + pid + " (" + process.ProcessName + "). You probably don't have permission.");
                        continue;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Error: unhandled exception killing process by process ID: " + pid + " (Name: " + process.ProcessName + ")");
                        Console.WriteLine(e);
                        continue;
                    }
                }
                else // process(es) by name
                {
                    string name = arg;
                    if (arg.EndsWith(".exe"))
                    {
                        name = String.Concat(arg.Reverse().Skip(4).Reverse()); // just wanna remove the .exe at the end :(
                    }
                    Process[] processes = Process.GetProcessesByName(name);
                    if (processes.Length == 0)
                    {
                        Console.WriteLine("[!] Error: no process exists with name: " + arg);
                        continue;
                    }
                    foreach (Process process in processes)
                    {
                        try
                        {
                            process.Kill();
                            Console.WriteLine("[*] Killed process " + process.Id + " (" + process.ProcessName + ")");
                        }
                        catch (Win32Exception)
                        {
                            Console.WriteLine("[!] Error: could not kill process by name: " + process.ProcessName + " (PID: " + process.Id + "). You might not have permission.");
                            continue;
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("Error: unhandled exception killing process by name: " + process.ProcessName + " (PID: " + process.Id + ")");
                            Console.WriteLine(e);
                            continue;
                        }
                    }
                }
            }
            return 0;
        }

        public static int Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("Processes options:");
                Console.WriteLine("ps, kill");
                Console.WriteLine("To view help for a sub-command, do Processes <cmd> -h");
                return 0;
            }
            string cmd = args[0].ToLower();
            args = args.Skip(1).Take(args.Length).ToArray(); // cut off the first element in the args[] array
            switch (cmd)
            {
                case "ps":
                    return Ps(args);
                case "kill":
                    return Kill(args);
                default:
                    Console.WriteLine("[!] Invalid sub-command selection: " + cmd);
                    return 0;
            }
        }
    }
}
