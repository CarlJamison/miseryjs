using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SocketIOClient;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            DoStuff();
            while(true) { };
        }
        static async void DoStuff()
        {
            var client = new SocketIO("http://192.168.1.6:3000/client");

            await client.ConnectAsync();

            client.On("message", response =>
            {
                Console.WriteLine(response);
                client.EmitAsync("message", response + "!");
            });

            
        }
    }
}
