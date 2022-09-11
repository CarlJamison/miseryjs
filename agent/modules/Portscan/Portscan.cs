using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Collections;
using System.Threading;

namespace Portscan
{
    public class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length != 2)
            {
                Usage();
            }
            else
            {
                var results = PortScan(args[0], ParsePort(args[1]));
                Console.WriteLine(results);
                Console.WriteLine("\nScanning complete...");
            }
            return 0;
        }

        static List<int> ParsePort(string portString)
        {
            List<int> parsed = new List<int> { };
            var sections = portString.Split(',');
            foreach (string section in sections)
            {
                // Split the range (1-1024) into two substrings ("1", "1024"), try to parse as ints, then add each value in the range to the list
                if (section.Contains("-"))
                {
                    string[] range = section.Split('-');

                    int start;
                    int end;
                    if (!int.TryParse(range[0], out start))
                    {
                        Console.WriteLine("Failed to convert port string to integer list");
                        return new List<int> { };
                    }

                    if (!int.TryParse(range[1], out end))
                    {
                        Console.WriteLine("Failed to convert port string to integer list");
                        return new List<int> { };
                    }
                    for (int i = start; i <= end; i++)
                    {
                        parsed.Add(i);
                    }
                }

                // Raw value ... just add to list
                else
                {
                    int result;
                    if (!int.TryParse(section, out result))
                    {
                        Console.WriteLine("Failed to convert port string to integer list");
                        return new List<int> { };
                    }
                    parsed.Add(result);
                }
            }
            return parsed;
        }
        static void Usage()
        {
            Console.WriteLine("Portscan a host or IP range on certain ports");
            Console.WriteLine("Portscan <Host> <Port>");
            Console.WriteLine("Portscan <Range> <Ports>");
            Console.WriteLine("Example: Portscan.exe 192.168.0.0/24 22,80,443-445");
        }

        public class ResultList<T> : IList<T> where T : Result
        {
            private List<T> Results { get; } = new List<T>();

            public int Count => Results.Count;
            public bool IsReadOnly => ((IList<T>)Results).IsReadOnly;


            private const int PROPERTY_SPACE = 3;

            /// <summary>
            /// Formats a ResultList to a string similar to PowerShell's Format-List function.
            /// </summary>
            /// <returns>string</returns>
            public string FormatList()
            {
                return this.ToString();
            }

            private string FormatTable()
            {
                // TODO
                return "";
            }

            /// <summary>
            /// Formats a ResultList as a string. Overrides ToString() for convenience.
            /// </summary>
            /// <returns>string</returns>
            public override string ToString()
            {
                if (this.Results.Count > 0)
                {
                    StringBuilder labels = new StringBuilder();
                    StringBuilder underlines = new StringBuilder();
                    List<StringBuilder> rows = new List<StringBuilder>();
                    for (int i = 0; i < this.Results.Count; i++)
                    {
                        rows.Add(new StringBuilder());
                    }
                    for (int i = 0; i < this.Results[0].ResultProperties.Count; i++)
                    {
                        labels.Append(this.Results[0].ResultProperties[i].Name);
                        underlines.Append(new string('-', this.Results[0].ResultProperties[i].Name.Length));
                        int maxproplen = 0;
                        for (int j = 0; j < rows.Count; j++)
                        {
                            ResultProperty property = this.Results[j].ResultProperties[i];
                            string ValueString = property.Value.ToString();
                            rows[j].Append(ValueString);
                            if (maxproplen < ValueString.Length)
                            {
                                maxproplen = ValueString.Length;
                            }
                        }
                        if (i != this.Results[0].ResultProperties.Count - 1)
                        {
                            labels.Append(new string(' ', Math.Max(2, maxproplen + 2 - this.Results[0].ResultProperties[i].Name.Length)));
                            underlines.Append(new string(' ', Math.Max(2, maxproplen + 2 - this.Results[0].ResultProperties[i].Name.Length)));
                            for (int j = 0; j < rows.Count; j++)
                            {
                                ResultProperty property = this.Results[j].ResultProperties[i];
                                string ValueString = property.Value.ToString();
                                rows[j].Append(new string(' ', Math.Max(this.Results[0].ResultProperties[i].Name.Length - ValueString.Length + 2, maxproplen - ValueString.Length + 2)));
                            }
                        }
                    }
                    labels.AppendLine();
                    labels.Append(underlines.ToString());
                    foreach (StringBuilder row in rows)
                    {
                        labels.AppendLine();
                        labels.Append(row.ToString());
                    }
                    return labels.ToString();
                }
                return "";
            }

            public T this[int index] { get => Results[index]; set => Results[index] = value; }

            public IEnumerator<T> GetEnumerator()
            {
                return Results.Cast<T>().GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return Results.Cast<T>().GetEnumerator();
            }

            public int IndexOf(T item)
            {
                return Results.IndexOf(item);
            }

            public void Add(T t)
            {
                Results.Add(t);
            }

            public void AddRange(IEnumerable<T> range)
            {
                Results.AddRange(range);
            }

            public void Insert(int index, T item)
            {
                Results.Insert(index, item);
            }

            public void RemoveAt(int index)
            {
                Results.RemoveAt(index);
            }

            public void Clear()
            {
                Results.Clear();
            }

            public bool Contains(T item)
            {
                return Results.Contains(item);
            }

            public void CopyTo(T[] array, int arrayIndex)
            {
                Results.CopyTo(array, arrayIndex);
            }

            public bool Remove(T item)
            {
                return Results.Remove(item);
            }
        }

        /// <summary>
        /// Abstract class that represents a result from a SharpSploit function.
        /// </summary>
        public abstract class Result
        {
            protected internal abstract IList<ResultProperty> ResultProperties { get; }
        }

        /// <summary>
        /// ResultProperty represents a property that is a member of a Result's ResultProperties.
        /// </summary>
        public class ResultProperty
        {
            public string Name { get; set; }
            public object Value { get; set; }
        }

        public sealed class GenericObjectResult : Result
        {
            public object Result { get; }
            protected internal override IList<ResultProperty> ResultProperties
            {
                get
                {
                    return new List<ResultProperty>
                    {
                        new ResultProperty
                        {
                            Name = this.Result.GetType().Name,
                            Value = this.Result
                        }
                    };
                }
            }

            public GenericObjectResult(object Result)
            {
                this.Result = Result;
            }
        }

        public sealed class PortScanResult : Result
        {
            public string ComputerName { get; } = "";
            public int Port { get; } = 0;
            public bool IsOpen { get; set; } = false;
            protected internal override IList<ResultProperty> ResultProperties
            {
                get
                {
                    return new List<ResultProperty>
                    {
                        new ResultProperty
                        {
                            Name = "ComputerName",
                            Value = this.ComputerName
                        },
                        new ResultProperty
                        {
                            Name = "Port",
                            Value = this.Port
                        },
                        new ResultProperty
                        {
                            Name = "IsOpen",
                            Value = this.IsOpen
                        }
                    };
                }
            }

            public PortScanResult(string ComputerName = "", int Port = 0, bool IsOpen = false)
            {
                this.ComputerName = ComputerName;
                this.Port = Port;
                this.IsOpen = IsOpen;
            }
        }

        public static ResultList<PortScanResult> PortScan(string ComputerNames, IList<int> Ports, int Timeout = 250, int Threads = 100)
        {
            IList<string> scanAddresses = ConvertCidrToIPs(ComputerNames).Distinct().ToList();
            IList<int> scanPorts = Ports.Where(P => P > 1 && P < 65536).Distinct().ToList();

            IList<PortScanResult> portScanResults = new List<PortScanResult>();
            using (CountdownEvent waiter = new CountdownEvent(scanAddresses.Count * Ports.Count))
            {
                object portScanResultsLock = new object();
                int runningThreads = 0;
                foreach (string ComputerName in scanAddresses)
                {
                    foreach (int Port in scanPorts)
                    {
                        TcpClient client = null;
                        if (!IsIP(ComputerName))
                        {
                            client = new TcpClient();
                        }
                        else
                        {
                            IPAddress.TryParse(ComputerName, out IPAddress address);
                            client = new TcpClient(address.AddressFamily);
                        }
                        PortScanResult portScanResult = new PortScanResult(ComputerName, Port, true);
                        while (runningThreads >= Threads)
                        {
                            waiter.WaitOne(Timeout);
                            runningThreads--;
                        }
                        IAsyncResult asyncResult = client.BeginConnect(ComputerName, Port, new AsyncCallback((state) => {
                            try
                            {
                                client.EndConnect(state);
                                client.Close();
                            }
                            catch
                            {
                                portScanResult.IsOpen = false;
                            }
                            if (portScanResult.IsOpen)
                            {
                                lock (portScanResultsLock)
                                {
                                    portScanResults.Add(portScanResult);
                                }
                            }
                            ((CountdownEvent)state.AsyncState).Signal();
                        }), waiter);
                        runningThreads++;
                    }
                }
                waiter.Wait(Timeout * scanAddresses.Count * Ports.Count);
            }
            ResultList<PortScanResult> results = new ResultList<PortScanResult>();
            results.AddRange(portScanResults);

            return results;
        }

        public sealed class CountdownEvent : IDisposable
        {
            private readonly ManualResetEvent _countEvent = new ManualResetEvent(false);
            private readonly ManualResetEvent _reachedCountEvent = new ManualResetEvent(false);
            private volatile int _maxCount;
            private volatile int _currentCount = 0;
            private volatile bool _isDisposed = false;

            public CountdownEvent(int count)
            {
                this._maxCount = count;
            }

            public bool Signal()
            {
                if (this._isDisposed)
                {
                    return false;
                }
                if (this._currentCount >= this._maxCount)
                {
                    return true;
                }
                if (Interlocked.Increment(ref _currentCount) >= this._maxCount)
                {
                    _reachedCountEvent.Set();
                    return true;
                }
                _countEvent.Set();
                return false;
            }

            public bool Wait(int timeout = Timeout.Infinite)
            {
                if (this._isDisposed)
                {
                    return false;
                }
                return _reachedCountEvent.WaitOne(timeout);
            }

            public bool WaitOne(int timeout = Timeout.Infinite)
            {
                if (this._isDisposed)
                {
                    return false;
                }
                return _countEvent.WaitOne(timeout);
            }

            public void Dispose()
            {
                this.Dispose(true);
                GC.SuppressFinalize(this);
            }

            public void Dispose(bool disposing)
            {
                if (!this._isDisposed)
                {
                    if (disposing)
                    {
                        ((IDisposable)_reachedCountEvent).Dispose();
                        ((IDisposable)_countEvent).Dispose();
                    }
                    this._isDisposed = true;
                }
            }
        }

        private static IList<string> ConvertCidrToIPs(string CidrComputerName)
        {
            if (CidrComputerName == null || CidrComputerName == "")
            {
                return new List<string>();
            }
            if (!IsCidr(CidrComputerName))
            {
                return new List<string> { CidrComputerName };
            }
            // credit - https://stackoverflow.com/questions/32028166
            string[] parts = CidrComputerName.Split('.', '/');
            uint ipasnum = (Convert.ToUInt32(parts[0]) << 24) | (Convert.ToUInt32(parts[1]) << 16) |
                           (Convert.ToUInt32(parts[2]) << 8) | (Convert.ToUInt32(parts[3]));
            int maskbits = Convert.ToInt32(parts[4]);
            uint mask = 0xffffffff;
            mask <<= (32 - maskbits);
            uint ipstart = ipasnum & mask;
            uint ipend = ipasnum | ~mask;
            List<string> IPAddresses = new List<string>();
            for (uint i = ipstart; i < ipend + 1; i++)
            {
                IPAddresses.Add(String.Format("{0}.{1}.{2}.{3}", i >> 24, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff));
            }
            return IPAddresses;
        }

        public static bool IsIP(string ComputerName)
        {
            return IPAddress.TryParse(ComputerName, out IPAddress address);
        }

        public static bool IsCidr(string ComputerName)
        {
            string[] parts = ComputerName.Split('.', '/');
            if (parts.Length != 5)
            {
                return false;
            }
            foreach (string part in parts)
            {
                if (!int.TryParse(part, out int i))
                {
                    return false;
                }
                if (i < 0 || i > 255)
                {
                    return false;
                }
            }
            if (!ComputerName.Contains("/"))
            {
                return false;
            }
            string ippart = ComputerName.Split('/')[0];
            return ippart.Split('.').Length == 4;
        }
    }
}

