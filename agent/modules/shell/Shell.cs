using System;
using System.Linq;
using System.Diagnostics;

namespace Shell
{
    public class Program
    {
        public static int Main(string[] args)
        {
            Process process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c " + parseArgs(args),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };
            process.Start();
            while (!process.StandardOutput.EndOfStream)
            {
                Console.WriteLine(process.StandardOutput.ReadLine());
            }
            while(!process.StandardError.EndOfStream)
            {
                Console.WriteLine(process.StandardError.ReadLine());
            }
            return 0;
        }
        private static string parseArgs(string[] args)
        {
            string result = "";
            int count = 1;

            // basically just wrap args that contain spaces in quotes. All others, just add to the string
            foreach(string arg in args)
            {
                if(arg.Contains(' '))
                {
                    result += '"' + arg + '"';
                }
                else
                {
                    result += arg;
                }
                if(count != args.Length)
                {
                    result += " ";
                }
                count++;
            }
            return result;
        }
    }
}

