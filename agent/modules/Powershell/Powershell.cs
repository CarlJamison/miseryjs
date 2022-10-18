using System;
using System.Linq;
using System.Text;
using System.Management.Automation;

// Make sure to include the Powershell DLL file as a reference before compiling this project.
// Copy System.Management.Automation.dll to your C: drive with the following Powershell command: copy ([psobject].Assembly.Location) C:\
// Add the reference in visual studio: Project > Add Reference > Browse > System.Management.Automation.dll

namespace Powershell
{
    public class Program
    {
        public static PowerShell ps = PowerShell.Create();
        public static int Main(string[] args)
        {
            if (args.Length < 2 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "/help")
            {
                Console.WriteLine("Powershell - Load and execute scripts and run Cmdlets");
                Console.WriteLine("Usage: Powershell load <base64 script>");
                Console.WriteLine("       Powershell run <powershell Cmdlet> [Cmdlet arguments ...]");
            }
            else
            {
                string cmd = args[0].ToLower();
                args = args.Skip(1).Take(args.Length).ToArray(); // cut off the first element in the args[] array
                if (cmd == "load")
                {
                    Psh(args[0], ps, encoded: true);
                }
                else if (cmd == "run")
                {
                    Psh(String.Join(" ", args), ps);
                }
                else
                {
                    Console.WriteLine("[!] Invalid sub-command selection: " + cmd);
                }
            }
            return 0;
        }
        private static void Psh(string script, PowerShell ps, bool encoded = false)
        {
            System.Collections.ObjectModel.Collection<PSObject> output;
            if (encoded)
            {
                try
                {
                    script = Encoding.UTF8.GetString(Convert.FromBase64String(script));
                }
                catch
                {
                    Console.WriteLine($"[!] Can't execute Powershell: Malformed base64: {Truncate(script, 100)}");
                    return;
                }
            }
            try
            {
                Console.WriteLine(script);
                output = ps.AddScript(script).Invoke();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[!] Error in executing powershell: {e}");
                return;
            }
            if (ps.Streams.Error.Count != 0)
            {
                Console.WriteLine("[!] Error in script:");
            }
            foreach (ErrorRecord e in ps.Streams.Error)
            {
                Console.WriteLine(e.ToString());
            }
            foreach (PSObject item in output)
            {
                Console.WriteLine(item.ToString());
            }

            ps.Streams.Error.Clear();
            ps.Commands.Clear(); // Reset the errors to empty so we don't get flooded with errors upon subsequent invocations
        }
        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return value;
            return value.Length <= maxLength ? value : value.Substring(0, maxLength) + "...";
        }
    }
}

