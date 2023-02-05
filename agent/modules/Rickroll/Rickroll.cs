using System;

namespace Program
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string url = "https://www.youtube.com/watch?v=a3Z7zEc7AXQ?autoplay=1";

            if (args.Length > 0)
            {
                if (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
                {
                    Usage();
                    return;
                }

                if (args.Length == 1)
                {
                    url = args[0];
                }
            }
            OpenUrl(url);

        }
        static void Usage()
        {
            Console.WriteLine("Rickrolls the client by default, or open any URL specified");
            Console.WriteLine("usage: Rickroll <url>");
        }
        static void OpenUrl(string url)
        {
            try
            {
                System.Diagnostics.Process.Start(url);
            }
            catch (System.ComponentModel.Win32Exception noBrowser)
            {
                if (noBrowser.ErrorCode == -2147467259)
                    Console.WriteLine(noBrowser.Message);
            }
            catch (System.Exception other)
            {
                Console.WriteLine(other.Message);
            }
        }

    }
}
