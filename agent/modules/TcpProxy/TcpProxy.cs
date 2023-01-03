using System.Linq;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;
using System.Collections.Generic;
using System.Text.Json;

namespace TcpProxy
{
    public class Program
    {

        public static int Main()
        {

            Console.WriteLine("Module needs to be streamed");
            return 0;
        }

        public static void Stream(Func<object, Task> cb, string[] args, Queue<JsonElement> queue)
        {
            while (true)
            {
                if (queue.Any())
                {
                    var message = queue.Dequeue();
                    var clientPair = new ClientPair();
                    try
                    {
                        clientPair.cb = cb;
                        clientPair.targetHost = args[0];
                        clientPair.targetPort = int.Parse(args[1]);
                        clientPair.message = message.GetProperty("data").ToString();
                        clientPair.id = message.GetProperty("connection_id").ToString();
                        clientPair.connectRetryCount = 0;
                        clientPair.disconnected = false;
                        clientPair.target = new TcpClient();
                        clientPair.target.BeginConnect(clientPair.targetHost, clientPair.targetPort, TargetConnect, clientPair);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Failed when trying to accept new clients with '{0}'", (object)ex.ToString());
                    }
                }
                Thread.Sleep(100);
            }
        }


        private static void TargetConnect(IAsyncResult asyncResult)
        {
            var clientPair = asyncResult.AsyncState != null
                ? (ClientPair)asyncResult.AsyncState
                : throw new ArgumentNullException(nameof(asyncResult));
            try
            {
                clientPair.target.EndConnect(asyncResult);
                clientPair.targetStream = clientPair.target.GetStream();

                SourceRead(clientPair);
                clientPair.targetStream.BeginRead(clientPair.targetBuffer, 0, clientPair.targetBuffer.Length,
                    TargetRead, clientPair);
            }
            catch (SocketException ex)
            {
                if (clientPair.connectRetryCount < 2)
                {
                    ++clientPair.connectRetryCount;
                    clientPair.target.BeginConnect(clientPair.targetHost, clientPair.targetPort, TargetConnect, clientPair);
                    Console.WriteLine("Retrying connect");
                }
                else
                {
                    Console.WriteLine("Connection failed: {0}", (object)ex.ToString());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed connecting to target with '{0}'", (object)ex.ToString());
            }
        }

        private static void SourceRead(ClientPair asyncState)
        {
            try
            {
                var data = Convert.FromBase64String(asyncState.message);
                var count = data.Length;
                if (count > 0)
                {
                    if (asyncState.target.Connected)
                    {
                        asyncState.targetStream.BeginWrite(data, 0, count, TargetWrite, asyncState);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Client disconnected: '{0}'", (object)ex.Message);
            }
        }

        private static void TargetRead(IAsyncResult asyncResult)
        {
            var asyncState = asyncResult.AsyncState as ClientPair;
            if (!asyncState.disconnected && asyncState.target.Connected)
            {
                var count = asyncState.targetStream.EndRead(asyncResult);
                if (count > 0)
                {
                    asyncState.cb(new
                    {
                        asyncState.id,
                        data = Convert.ToBase64String(asyncState.targetBuffer.Take(count).ToArray())
                    });

                    try
                    {
                        asyncState.targetStream.BeginRead(asyncState.targetBuffer, 0, asyncState.targetBuffer.Length, TargetRead, asyncState);
                    }
                    catch
                    {
                        DisconnectPair(asyncState);
                    }
                }
                else
                {
                    DisconnectPair(asyncState);
                }
            }
        }

        private static void DisconnectPair(ClientPair pair)
        {
            if (pair.disconnected)
                return;
            try
            {
                try
                {
                    if (pair.target.Client.Connected)
                        pair.target.Client.Close();
                }
                catch { }

                if (!pair.disconnected)
                {
                    pair.disconnected = true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        private static void TargetWrite(IAsyncResult asyncResult)
        {
            var pair = asyncResult.AsyncState != null
                ? asyncResult.AsyncState as ClientPair
                : throw new ArgumentNullException(nameof(asyncResult));

            try
            {
                pair.targetStream.EndWrite(asyncResult);
            }
            catch
            {
                if (!pair.disconnected)
                    DisconnectPair(pair);
            }
        }
    }
}

internal class ClientPair
{
    public string targetHost;
    public int targetPort;
    public Func<object, Task> cb;
    public string id;
    public string message;
    public readonly byte[] targetBuffer = new byte[65536];
    public int connectRetryCount;
    public bool disconnected;
    public TcpClient target;
    public NetworkStream targetStream;
}