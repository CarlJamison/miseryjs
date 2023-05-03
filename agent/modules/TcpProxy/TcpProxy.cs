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
                    var connectionId = message["connection_id"];

                    if (message.ContainsKey("data"))
                    {
                        var existingJob = jobs.FirstOrDefault(j => j.Id == connectionId);
                        if (existingJob != null)
                        {
                            WriteToStream(existingJob.Stream, message, targetPort, targetHost);
                        }
                        else
                        {
                            var newJob = new Job
                            {
                                Id = connectionId
                            };
                            newJob.Thread = new Thread(() => OpenConnection(cb, message, targetPort, targetHost, newJob));
                            newJob.Thread.Start();
                            jobs.Add(newJob);
                        }
                    }
                    else
                    {
                        var job = jobs.FirstOrDefault(j => j.Id == connectionId);

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

        private static void OpenConnection(Func<object, Task> cb, Dictionary<string, string> response, int targetPort, string targetHost, Job job)
        {
            try
            {
                TcpClient tcpClient = new TcpClient();
                tcpClient.Connect(targetHost, targetPort);
                Stream networkStream = null;

                if (false && targetPort == 443)
                {
                    var coolSSLThing = new SslStream(tcpClient.GetStream());
                    coolSSLThing.AuthenticateAsClient(targetHost);
                    networkStream = coolSSLThing;
                }
                else
                {
                    networkStream = tcpClient.GetStream();
                }

                job.Stream = networkStream;
                job.Client = tcpClient;

                WriteToStream(networkStream, response, targetPort, targetHost);

                var targetBuffer = new byte[65536];

                while (tcpClient.Connected)
                {
                    var count = networkStream.Read(targetBuffer, 0, targetBuffer.Length);
                    if (count > 0)
                    {
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
                    Thread.Sleep(10);
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

        private static void WriteToStream(Stream networkStream, Dictionary<string, string> message, int targetPort, string targetHost)
        {
            var bytes = Convert.FromBase64String(message["data"]);

            /*if (targetPort == 443 || targetPort == 80)
            {
                var coolString = System.Text.Encoding.UTF8.GetString(bytes).Replace("{ClientHost}", targetHost);
                bytes = System.Text.Encoding.UTF8.GetBytes(coolString);
            }*/

            networkStream.Write(bytes, 0, bytes.Length);
        }

        public class Job
        {
            public string Id;
            public Thread Thread;
            public Stream Stream;
            public TcpClient Client;
        }

    }
}