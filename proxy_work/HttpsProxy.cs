using SocketIOClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;

namespace HttpsProxy
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            if (args.Any())
            {
                Go(args[0]);
            }
            else
            {
                Go();
            }
            while (true) { };
        }

        static async void Go(string home = "http://localHost:8000/", int targetPort = 443, string targetHost = "www.google.com")
        {
            List<Job> jobs = new List<Job>();
            var client = new SocketIO(home);
            await client.ConnectAsync();
            client.On("echo", response =>
            {
                Thread myNewThread = new Thread(() => OpenConnection(client, response, targetPort, targetHost));
                myNewThread.Start();
                jobs.Add(new Job
                {
                    Id = response.GetValue(0).GetProperty("id").GetInt32(),
                    Thread = myNewThread
                });
            });

            client.On("close", response =>
            {
                var job = jobs.FirstOrDefault(j => j.Id == response.GetValue(0).GetProperty("id").GetInt32());

                if (job != null)
                {
                    job.Thread.Abort();
                    jobs.Remove(job);
                }
            });
        }

        private static void OpenConnection(SocketIO client, SocketIOResponse response, int targetPort, string targetHost)
        {
            try
            {
                TcpClient tcpClient = new TcpClient();
                tcpClient.Connect(targetHost, targetPort);
                NetworkStream netStream = tcpClient.GetStream();
                var coolString = System.Text.Encoding.UTF8.GetString(
                    Convert.FromBase64String(
                    response.GetValue(0).GetProperty("data").ToString()));

                coolString = coolString.Replace("localhost:5000", targetHost);

                var sendBytes = System.Text.Encoding.UTF8.GetBytes(coolString);
                Console.WriteLine(coolString);

                var networkStream = new SslStream(netStream);
                networkStream.AuthenticateAsClient(targetHost);
                networkStream.Write(sendBytes, 0, sendBytes.Length);

                var targetBuffer = new byte[65536];

                while (tcpClient.Connected)
                {
                    var count = networkStream.Read(targetBuffer, 0, targetBuffer.Length);
                    Console.WriteLine("Response Received");
                    client.EmitAsync("echo", new
                    {
                        id = response.GetValue(0).GetProperty("id").GetInt32(),
                        data = Convert.ToBase64String(targetBuffer.Take(count).ToArray())
                    });
                }

                tcpClient.Close();
                networkStream.Close();
                tcpClient.Dispose();
                networkStream.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed when trying to accept new clients with '{0}'", (object)ex.ToString());
            }
        }
    }

    public class Job
    {
        public int Id;
        public Thread Thread;
    }
}