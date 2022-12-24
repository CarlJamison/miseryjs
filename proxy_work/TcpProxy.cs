using SocketIOClient;
using System.Net.Sockets;

namespace TcpProxy
{
    public class Program
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

        static async void Go(string home = "http://localHost:8000/", int targetPort = 3000, string targetHost = "localHost")
        {
            var client = new SocketIO(home);
            await client.ConnectAsync();
            new TcpPortForwarder(client, targetPort, targetHost).Start();
        }
    }
    internal sealed class TcpPortForwarder
    {
        private readonly SocketIO client;
        private readonly string _targetHost;
        private readonly int _targetPort;

        public TcpPortForwarder(SocketIO sio, int targetPort, string targetHost)
        {
            client = sio;
            _targetPort = targetPort;
            _targetHost = targetHost;
        }

        public void Start()
        {
            client.On("echo", response =>
            {
                var clientPair = new ClientPair();
                try
                {
                    clientPair.message = response.GetValue(0).GetProperty("data").ToString();
                    clientPair.id = response.GetValue(0).GetProperty("id").GetInt32();
                    clientPair.connectRetryCount = 0;
                    clientPair.disconnected = false;
                    clientPair.target = new TcpClient();
                    clientPair.target.BeginConnect(_targetHost, _targetPort, TargetConnect, clientPair);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed when trying to accept new clients with '{0}'", (object)ex.ToString());
                }
            });
        }

        private void TargetConnect(IAsyncResult asyncResult)
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
                    clientPair.target.BeginConnect(_targetHost, _targetPort, TargetConnect, clientPair);
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

        private void SourceRead(ClientPair asyncState)
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

        private void TargetRead(IAsyncResult asyncResult)
        {
            var asyncState = asyncResult.AsyncState as ClientPair;
            if (!asyncState.disconnected && asyncState.target.Connected)
            {
                var count = asyncState.targetStream.EndRead(asyncResult);
                if (count > 0)
                {
                    client.EmitAsync("echo", new
                    {
                        id = asyncState.id,
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

        private void DisconnectPair(ClientPair pair)
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
                catch {}

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

        private void TargetWrite(IAsyncResult asyncResult)
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

    internal class ClientPair
    {
        public int id;
        public string message;
        public readonly byte[] sourceBuffer = new byte[65536];
        public readonly byte[] targetBuffer = new byte[65536];
        public int connectRetryCount;
        public bool disconnected;
        public TcpClient target;
        public NetworkStream targetStream;
    }
}