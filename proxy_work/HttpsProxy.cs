using SocketIOClient;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Text.Json;
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

        static async void Go(string home = "http://localHost:8000/", int targetPort = 4000, string targetHost = "localhost")
        {
            List<Job> jobs = new List<Job>();
            var client = new SocketIO(home);
            await client.ConnectAsync();
            client.On("echo", response =>
            {
                Thread myNewThread = new Thread(() => OpenConnection(client, response.GetValue(0), targetPort, targetHost));
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

        private static void OpenConnection(SocketIO client, JsonElement response, int targetPort, string targetHost)
        {
            try
            {
                TcpClient tcpClient = new TcpClient();
                tcpClient.Connect(targetHost, targetPort);
                Stream networkStream = null;

                if(targetPort == 443)
                {
                    var coolSSLThing = new SslStream(tcpClient.GetStream());
                    coolSSLThing.AuthenticateAsClient(targetHost);
                    networkStream = coolSSLThing;
                }
                else
                {
                    networkStream = tcpClient.GetStream();
                }

                var bytes = Convert.FromBase64String(response.GetProperty("data").ToString());

                if (targetPort == 443 || targetPort == 80)
                {
                    var coolString = System.Text.Encoding.UTF8.GetString(bytes).Replace("{ClientHost}", targetHost);
                    bytes = System.Text.Encoding.UTF8.GetBytes(coolString);
                }

                networkStream.Write(bytes, 0, bytes.Length);

                var targetBuffer = new byte[65536];

                while (tcpClient.Connected)
                {
                    var count = networkStream.Read(targetBuffer, 0, targetBuffer.Length);
                    client.EmitAsync("echo", new
                    {
                        id = response.GetProperty("id").GetInt32(),
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