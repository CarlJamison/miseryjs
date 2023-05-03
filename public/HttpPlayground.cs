using System.Linq;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;

namespace TcpProxy
{
    public class Program
    {
        public static string request = "GET / HTTP/1.1\r\nHost: localhost:3000\r\nConnection: keep-alive\r\r\n\r\n";

        public static int Main()
        {
            var targetHost = "google.com";
            var targetPort = 443;
            TcpClient tcpClient = new TcpClient();
            tcpClient.Connect(targetHost, targetPort);
            Stream networkStream = null;

            //Protocol Specific -- Bad
            if (targetPort == 443)
            {
                var coolSSLThing = new SslStream(tcpClient.GetStream());
                coolSSLThing.AuthenticateAsClient(targetHost);
                networkStream = coolSSLThing;
            }
            else
            {
                networkStream = tcpClient.GetStream();
            }

            //Protocol Specific -- Bad
            request = request.Replace("localhost:3000", targetHost);

            var plainBytes = System.Text.Encoding.UTF8.GetBytes(request);
            var message = Convert.ToBase64String(plainBytes);
            var bytes = Convert.FromBase64String(message);

            networkStream.Write(bytes, 0, bytes.Length);

            var targetBuffer = new byte[65536];

            while (tcpClient.Connected)
            {
                var count = networkStream.Read(targetBuffer, 0, targetBuffer.Length);
                if (count > 0)
                {
                    Console.Write(System.Text.Encoding.UTF8.GetString(targetBuffer.Take(count).ToArray()));
                }
                Thread.Sleep(10);
            }

            tcpClient.Close();
            networkStream.Close();
            tcpClient.Dispose();
            networkStream.Close();
            return 0;
        }

    }
}