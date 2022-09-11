using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtOpenProcess(
            ref IntPtr ProcessHandle,
            DI.Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
            ref Win32.OBJECT_ATTRIBUTES ObjectAttributes,
            ref Win32.CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint BufferLength,
            ref uint BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            ref uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtCreateThreadEx(
            ref IntPtr threadHandle,
            DI.Data.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtWaitForSingleObject(
            IntPtr ObjectHandle,
            bool Alertable,
            uint Timeout);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtFreeVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint freeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtFlushInstructionCache(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            uint NumberOfBytesToFlush);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            ref PROCESS_BASIC_INFORMATION ProcessInformation,
            uint ProcessInformationLength,
            ref uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            ref uint NumberOfBytesReaded);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtResumeThread(
            IntPtr ThreadHandle,
            ref uint SuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtOpenThread(
            ref IntPtr ThreadHandle,
            DI.Data.Win32.Kernel32.ThreadAccess dwDesiredAccess,
            ref Win32.OBJECT_ATTRIBUTES ObjectAttributes,
            ref Win32.CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtAlertResumeThread(
            IntPtr ThreadHandle,
            ref uint SuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtGetContextThread(
            IntPtr hThread,
            ref Registers.CONTEXT64 lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtSetContextThread(
            IntPtr hThread,
            ref Registers.CONTEXT64 lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtCreateSection(
            ref IntPtr SectionHandle,
            DI.Data.Win32.WinNT.ACCESS_MASK DesiredAccess,
            IntPtr ObjectAttributes,
            ref UInt32 MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            UIntPtr CommitSize,
            ref ulong SectionOffset,
            ref uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS RtlCreateUserThread(
            IntPtr ProcessHandle,
            IntPtr ThreadSecurity,
            bool CreateSuspended,
            Int32 StackZeroBits,
            IntPtr StackReserved,
            IntPtr StackCommit,
            IntPtr StartAddress,
            IntPtr Parameter,
            ref IntPtr ThreadHandle,
            IntPtr ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtUnmapViewOfSection(
            IntPtr ProcessHandle,
            IntPtr BaseAddress);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtClose(IntPtr ObjectHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DeleteProcThreadAttributeList(
            IntPtr lpAttributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcessA(
            string lpApplicationName,
            string lpCommandLine,
            ref DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref DI.Data.Win32.ProcessThreadsAPI._STARTUPINFOEX lpStartupInfoEx,
            out DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool GetModuleInformation(
            IntPtr hProcess,
            IntPtr hModule,
            out Win32.MODULEINFO lpmodinfo,
            uint cb);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualProtect(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void CopyMemory(
            IntPtr destination,
            IntPtr source,
            uint length);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool OpenClipboard(IntPtr hWndNewOwner);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr SetClipboardData(
            uint uFormat,
            byte[] hMem);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CloseClipboard();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr HeapCreate(
            uint flOptions,
            UIntPtr dwInitialSize,
            UIntPtr dwMaximumSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr UuidFromStringA(
            string stringUuid,
            IntPtr heapPointer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool EnumSystemLocalesA(
            IntPtr lpLocaleEnumProc,
            int dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool EnumTimeFormatsEx(
            IntPtr lpTimeFmtEnumProcEx,
            IntPtr lpLocaleName,
            uint dwFlags,
            uint lParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint WaitForInputIdle(
            IntPtr hProcess,
            uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr FindWindowExA(
            IntPtr parentHandle,
            IntPtr hWndChildAfter,
            string className,
            string windowTitle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr SendMessageA(
            IntPtr hWnd,
            uint Msg,
            IntPtr wParam,
            ref Win32.COPYDATASTRUCT lParam);
    }
}
