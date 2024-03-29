﻿using System;
using System.Threading;
using Clipboard = System.Windows.Forms.Clipboard;

namespace ClipboardAccess
{
    public class Program
    {

        public static int Main(string[] args)
        {
            Thread thread = new Thread(() => Console.WriteLine(Clipboard.GetText()));
            thread.SetApartmentState(ApartmentState.STA); //Set the thread to STA
            thread.Start();
            thread.Join();
            
            return 0;
        }
    }
}
