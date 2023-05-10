using System.Linq;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;
using System.Collections.Generic;
using System.IO;

namespace SocksProxy
{
    public class Program
    {

        public static int Main()
        {
            Console.WriteLine("Module needs to be streamed");
            return 0;
        }

        public static void Stream(Func<object, Task> cb, Queue<Dictionary<string, string>> queue, int jobId)
        {
            List<Job> jobs = new List<Job>();
            cb(new
            {
                returnType = 8,
                output = new
                {
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
                            WriteToStream(existingJob.Stream, message);
                        }
                        else
                        {
                            var newJob = new Job
                            {
                                Id = connectionId
                            };
                            newJob.Thread = new Thread(() => OpenConnection(cb, message, newJob));
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

        private static void OpenConnection(Func<object, Task> cb, Dictionary<string, string> response, Job job)
        {
            try
            {
                TcpClient tcpClient = new TcpClient();
                tcpClient.Connect(response["host"], int.Parse(response["port"]));
                Stream networkStream = tcpClient.GetStream();

                job.Stream = networkStream;
                job.Client = tcpClient;

                WriteToStream(networkStream, response);

                var targetBuffer = new byte[65536];

                while (tcpClient.Connected)
                {
                    var count = networkStream.Read(targetBuffer, 0, targetBuffer.Length);
                    if (count > 0)
                    {
                        cb(new
                        {
                            returnType = 7,
                            output = new
                            {
                                data = Convert.ToBase64String(targetBuffer.Take(count).ToArray()),
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

        private static void WriteToStream(Stream networkStream, Dictionary<string, string> message)
        {
            var bytes = Convert.FromBase64String(message["data"]);
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