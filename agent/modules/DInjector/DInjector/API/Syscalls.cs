using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;
using static DInvoke.DynamicInvoke.Generic;

namespace DInjector
{
    class Syscalls
    {
        public static NTSTATUS NtOpenProcess(ref IntPtr ProcessHandle, DI.Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess, ref Win32.OBJECT_ATTRIBUTES ObjectAttributes, ref Win32.CLIENT_ID ClientId)
        {
            IntPtr stub = GetSyscallStub("ZwOpenProcess");
            Delegates.NtOpenProcess ntOpenProcess = (Delegates.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtOpenProcess));

            return ntOpenProcess(
                ref ProcessHandle,
                DesiredAccess,
                ref ObjectAttributes,
                ref ClientId);
        }

        public static NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect)
        {
            IntPtr stub = GetSyscallStub("ZwAllocateVirtualMemory");
            Delegates.NtAllocateVirtualMemory ntAllocateVirtualMemory = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtAllocateVirtualMemory));

            if (ProcessHandle == IntPtr.Zero)
                return ntAllocateVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref BaseAddress,
                    ZeroBits,
                    ref RegionSize,
                    AllocationType,
                    Protect);

            return ntAllocateVirtualMemory(
                ProcessHandle,
                ref BaseAddress,
                ZeroBits,
                ref RegionSize,
                AllocationType,
                Protect);
        }

        public static NTSTATUS NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint BufferLength, ref uint BytesWritten)
        {
            IntPtr stub = GetSyscallStub("ZwWriteVirtualMemory");
            Delegates.NtWriteVirtualMemory ntWriteVirtualMemory = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtWriteVirtualMemory));

            return ntWriteVirtualMemory(
                ProcessHandle,
                BaseAddress,
                Buffer,
                BufferLength,
                ref BytesWritten);
        }

        public static NTSTATUS NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect)
        {
            IntPtr stub = GetSyscallStub("ZwProtectVirtualMemory");
            Delegates.NtProtectVirtualMemory ntProtectVirtualMemory = (Delegates.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtProtectVirtualMemory));

            if (ProcessHandle == IntPtr.Zero)
                return ntProtectVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref BaseAddress,
                    ref RegionSize,
                    NewProtect,
                    ref OldProtect);

            return ntProtectVirtualMemory(
                ProcessHandle,
                ref BaseAddress,
                ref RegionSize,
                NewProtect,
                ref OldProtect);
        }

        public static NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle, DI.Data.Win32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            IntPtr stub = GetSyscallStub("ZwCreateThreadEx");
            Delegates.NtCreateThreadEx ntCreateThreadEx = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtCreateThreadEx));

            if (processHandle == IntPtr.Zero)
                return ntCreateThreadEx(
                    ref threadHandle,
                    desiredAccess,
                    objectAttributes,
                    Process.GetCurrentProcess().Handle,
                    startAddress,
                    parameter,
                    createSuspended,
                    stackZeroBits,
                    sizeOfStack,
                    maximumStackSize,
                    attributeList);

            return ntCreateThreadEx(
                ref threadHandle,
                desiredAccess,
                objectAttributes,
                processHandle,
                startAddress,
                parameter,
                createSuspended,
                stackZeroBits,
                sizeOfStack,
                maximumStackSize,
                attributeList);
        }

        public static NTSTATUS NtWaitForSingleObject(IntPtr ObjectHandle, bool Alertable, uint Timeout)
        {
            IntPtr stub = GetSyscallStub("NtWaitForSingleObject");
            Delegates.NtWaitForSingleObject ntWaitForSingleObject = (Delegates.NtWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtWaitForSingleObject));

            return ntWaitForSingleObject(
                ObjectHandle,
                Alertable,
                Timeout);
        }

        public static NTSTATUS NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)
        {
            IntPtr stub = GetSyscallStub("ZwFreeVirtualMemory");
            Delegates.NtFreeVirtualMemory ntFreeVirtualMemory = (Delegates.NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtFreeVirtualMemory));

            if (processHandle == IntPtr.Zero)
                return ntFreeVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref baseAddress,
                    ref regionSize,
                    freeType);

            return ntFreeVirtualMemory(
                processHandle,
                ref baseAddress,
                ref regionSize,
                freeType);
        }

        public static NTSTATUS NtFlushInstructionCache(IntPtr ProcessHandle, ref IntPtr BaseAddress, uint NumberOfBytesToFlush)
        {
            IntPtr stub = GetSyscallStub("ZwFlushInstructionCache");
            Delegates.NtFlushInstructionCache ntFlushInstructionCache = (Delegates.NtFlushInstructionCache)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtFlushInstructionCache));

            if (ProcessHandle == IntPtr.Zero)
                return ntFlushInstructionCache(
                    Process.GetCurrentProcess().Handle,
                    ref BaseAddress,
                    NumberOfBytesToFlush);

            return ntFlushInstructionCache(
                ProcessHandle,
                ref BaseAddress,
                NumberOfBytesToFlush);
        }

        public static NTSTATUS NtQueryInformationProcess(IntPtr ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, ref PROCESS_BASIC_INFORMATION ProcessInformation, uint ProcessInformationLength, ref uint ReturnLength)
        {
            IntPtr stub = GetSyscallStub("ZwQueryInformationProcess");
            Delegates.NtQueryInformationProcess ntQueryInformationProcess = (Delegates.NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtQueryInformationProcess));

            return ntQueryInformationProcess(
                ProcessHandle,
                ProcessInformationClass,
                ref ProcessInformation,
                ProcessInformationLength,
                ref ReturnLength);
        }

        public static NTSTATUS NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint NumberOfBytesToRead, ref uint NumberOfBytesReaded)
        {
            IntPtr stub = GetSyscallStub("ZwReadVirtualMemory");
            Delegates.NtReadVirtualMemory ntReadVirtualMemory = (Delegates.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtReadVirtualMemory));

            return ntReadVirtualMemory(
                ProcessHandle,
                BaseAddress,
                Buffer,
                NumberOfBytesToRead,
                ref NumberOfBytesReaded);
        }

        public static NTSTATUS NtResumeThread(IntPtr ThreadHandle, ref uint SuspendCount)
        {
            IntPtr stub = GetSyscallStub("ZwResumeThread");
            Delegates.NtResumeThread ntResumeThread = (Delegates.NtResumeThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtResumeThread));

            return ntResumeThread(
                ThreadHandle,
                ref SuspendCount);
        }

        public static NTSTATUS NtOpenThread(ref IntPtr ThreadHandle, DI.Data.Win32.Kernel32.ThreadAccess dwDesiredAccess, ref Win32.OBJECT_ATTRIBUTES ObjectAttributes, ref Win32.CLIENT_ID ClientId)
        {
            IntPtr stub = GetSyscallStub("ZwOpenThread");
            Delegates.NtOpenThread ntOpenThread = (Delegates.NtOpenThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtOpenThread));

            return ntOpenThread(
                ref ThreadHandle,
                dwDesiredAccess,
                ref ObjectAttributes,
                ref ClientId);
        }

        public static NTSTATUS NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3)
        {
            IntPtr stub = GetSyscallStub("ZwQueueApcThread");
            Delegates.NtQueueApcThread ntQueueApcThread = (Delegates.NtQueueApcThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtQueueApcThread));

            return ntQueueApcThread(
                ThreadHandle,
                ApcRoutine,
                ApcArgument1,
                ApcArgument2,
                ApcArgument3);
        }

        public static NTSTATUS NtAlertResumeThread(IntPtr ThreadHandle, ref uint SuspendCount)
        {
            IntPtr stub = GetSyscallStub("ZwAlertResumeThread");
            Delegates.NtAlertResumeThread ntAlertResumeThread = (Delegates.NtAlertResumeThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtAlertResumeThread));

            return ntAlertResumeThread(
                ThreadHandle,
                ref SuspendCount);
        }

        public static NTSTATUS NtGetContextThread(IntPtr hThread, ref Registers.CONTEXT64 lpContext)
        {
            IntPtr stub = GetSyscallStub("ZwGetContextThread");
            Delegates.NtGetContextThread ntGetContextThread = (Delegates.NtGetContextThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtGetContextThread));

            return ntGetContextThread(
                hThread,
                ref lpContext);
        }

        public static NTSTATUS NtSetContextThread(IntPtr hThread, ref Registers.CONTEXT64 lpContext)
        {
            IntPtr stub = GetSyscallStub("ZwGetContextThread");
            Delegates.NtSetContextThread ntSetContextThread = (Delegates.NtSetContextThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtSetContextThread));

            return ntSetContextThread(
                hThread,
                ref lpContext);
        }

        public static NTSTATUS NtCreateSection(ref IntPtr SectionHandle, DI.Data.Win32.WinNT.ACCESS_MASK DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle)
        {
            IntPtr stub = GetSyscallStub("ZwCreateSection");
            Delegates.NtCreateSection ntCreateSection = (Delegates.NtCreateSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtCreateSection));

            return ntCreateSection(
                ref SectionHandle,
                DesiredAccess,
                ObjectAttributes,
                ref MaximumSize,
                SectionPageProtection,
                AllocationAttributes,
                FileHandle);
        }

        public static NTSTATUS NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, ref ulong SectionOffset, ref uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect)
        {
            IntPtr stub = GetSyscallStub("ZwMapViewOfSection");
            Delegates.NtMapViewOfSection ntMapViewOfSection = (Delegates.NtMapViewOfSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtMapViewOfSection));

            if (ProcessHandle == IntPtr.Zero)
                return ntMapViewOfSection(
                    SectionHandle,
                    Process.GetCurrentProcess().Handle,
                    ref BaseAddress,
                    ZeroBits,
                    CommitSize,
                    ref SectionOffset,
                    ref ViewSize,
                    InheritDisposition,
                    AllocationType,
                    Win32Protect);

            return ntMapViewOfSection(
                SectionHandle,
                ProcessHandle,
                ref BaseAddress,
                ZeroBits,
                CommitSize,
                ref SectionOffset,
                ref ViewSize,
                InheritDisposition,
                AllocationType,
                Win32Protect);
        }

        public static NTSTATUS NtUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress)
        {
            IntPtr stub = GetSyscallStub("ZwUnmapViewOfSection");
            Delegates.NtUnmapViewOfSection ntUnmapViewOfSection = (Delegates.NtUnmapViewOfSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtUnmapViewOfSection));

            if (ProcessHandle == IntPtr.Zero)
                return ntUnmapViewOfSection(
                    Process.GetCurrentProcess().Handle,
                    BaseAddress);

            return ntUnmapViewOfSection(
                ProcessHandle,
                BaseAddress);
        }

        public static NTSTATUS NtClose(IntPtr ObjectHandle)
        {
            IntPtr stub = GetSyscallStub("ZwClose");
            Delegates.NtClose ntClose = (Delegates.NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtClose));

            return ntClose(ObjectHandle);
        }
    }
}
