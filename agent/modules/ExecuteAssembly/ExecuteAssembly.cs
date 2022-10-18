using System;
using System.Linq;
using System.Reflection;


namespace ExecuteAssembly
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Assembly assem = null;
            string data = args[0];
            args = args.Skip(1).Take(args.Length).ToArray(); // args[1:]
            try
            {
                assem = Assembly.Load(Convert.FromBase64String(data));
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Could not load assembly. Returned the following error:\n\n");
                Console.WriteLine(e);
            }

            if (args.Any())
            {
                Console.WriteLine("[*] Running assembly with arguments: " + string.Join(" ", args));
            }
            else
            {
                Console.WriteLine("[*] Running assembly with no arguments");
            }
            try
            {
                assem.EntryPoint.Invoke(null, new object[] { args });
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Could not invoke assembly. Returned the following error:\n\n");
                Console.WriteLine(e);
            }
        }
    }
}

