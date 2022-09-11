using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;
using static DInvoke.DynamicInvoke.Generic;

namespace DInjector
{
    class Win32
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocExNuma(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect,
            UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);

        public static bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, ref IntPtr lpSize)
        {
            object[] parameters = { lpAttributeList, dwAttributeCount, 0, lpSize };
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "InitializeProcThreadAttributeList", typeof(Delegates.InitializeProcThreadAttributeList), ref parameters);

            lpSize = (IntPtr)parameters[3];
            return result;
        }

        public static bool UpdateProcThreadAttribute(IntPtr lpAttributeList, IntPtr attribute, IntPtr lpValue)
        {
            object[] parameters = { lpAttributeList, (uint)0, attribute, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero };
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "UpdateProcThreadAttribute", typeof(Delegates.UpdateProcThreadAttribute), ref parameters, true);

            return result;
        }

        public static bool DeleteProcThreadAttributeList(IntPtr lpAttributeList)
        {
            object[] parameters = { lpAttributeList };
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "DeleteProcThreadAttributeList", typeof(Delegates.DeleteProcThreadAttributeList), ref parameters);

            return result;
        }

        public static bool CreateProcessA(string applicationName, string workingDirectory, uint creationFlags, DI.Data.Win32.ProcessThreadsAPI._STARTUPINFOEX startupInfoEx, out DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION processInformation)
        {
            var pa = new DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES();
            var ta = new DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES();
            var pi = new DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION();

            object[] parameters = { applicationName, null, pa, ta, false, creationFlags, IntPtr.Zero, workingDirectory, startupInfoEx, pi };
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "CreateProcessA", typeof(Delegates.CreateProcessA), ref parameters);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            processInformation = (DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION)parameters[9];

            return result;
        }

        public static bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb)
        {
            MODULEINFO mi = new MODULEINFO();

            object[] parameters = { hProcess, hModule, mi, cb };
            var result = (bool)DynamicAPIInvoke("psapi.dll", "GetModuleInformation", typeof(Delegates.GetModuleInformation), ref parameters);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            lpmodinfo = (MODULEINFO)parameters[2];

            return result;
        }

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            uint oldProtect = 0;

            object[] parameters = { lpAddress, dwSize, flNewProtect, oldProtect };
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "VirtualProtect", typeof(Delegates.VirtualProtect), ref parameters);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            lpflOldProtect = (uint)parameters[3];

            return result;
        }

        public static uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds)
        {
            object[] parameters = { hHandle, dwMilliseconds };
            var result = (uint)DynamicAPIInvoke("kernel32.dll", "WaitForSingleObject", typeof(Delegates.WaitForSingleObject), ref parameters);

            return result;
        }

        public static void CopyMemory(IntPtr destination, IntPtr source, uint length)
        {
            object[] parameters = { destination, source, length };
            _ = DynamicAPIInvoke("kernel32.dll", "RtlCopyMemory", typeof(Delegates.CopyMemory), ref parameters);
        }

        public static bool OpenClipboard(IntPtr hWndNewOwner)
        {
            object[] parameters = { hWndNewOwner };
            var result = (bool)DynamicAPIInvoke("user32.dll", "OpenClipboard", typeof(Delegates.OpenClipboard), ref parameters);

            return result;
        }

        public static IntPtr SetClipboardData(uint uFormat, byte[] hMem)
        {
            object[] parameters = { uFormat, hMem };
            var result = (IntPtr)DynamicAPIInvoke("user32.dll", "SetClipboardData", typeof(Delegates.SetClipboardData), ref parameters);

            return result;
        }

        public static bool CloseClipboard()
        {
            object[] parameters = { };
            var result = (bool)DynamicAPIInvoke("user32.dll", "CloseClipboard", typeof(Delegates.CloseClipboard), ref parameters);

            return result;
        }

        public static IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize)
        {
            object[] parameters = { flOptions, dwInitialSize, dwMaximumSize };
            var result = (IntPtr)DynamicAPIInvoke("kernel32.dll", "HeapCreate", typeof(Delegates.HeapCreate), ref parameters);

            return result;
        }

        public static IntPtr UuidFromStringA(string stringUuid, IntPtr heapPointer)
        {
            object[] parameters = { stringUuid, heapPointer };
            var result = (IntPtr)DynamicAPIInvoke("rpcrt4.dll", "UuidFromStringA", typeof(Delegates.UuidFromStringA), ref parameters);

            return result;
        }

        public static bool EnumSystemLocalesA(IntPtr lpLocaleEnumProc, int dwFlags)
        {
            object[] parameters = { lpLocaleEnumProc, dwFlags };
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "EnumSystemLocalesA", typeof(Delegates.EnumSystemLocalesA), ref parameters);

            return result;
        }

        public static bool EnumTimeFormatsEx(IntPtr lpTimeFmtEnumProcEx, IntPtr lpLocaleName, uint dwFlags, uint lParam)
        {
            object[] parameters = { lpTimeFmtEnumProcEx, lpLocaleName, dwFlags, lParam };
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "EnumTimeFormatsEx", typeof(Delegates.EnumTimeFormatsEx), ref parameters);

            return result;
        }

        public static uint WaitForInputIdle(IntPtr hProcess, uint dwMilliseconds)
        {
            object[] parameters = { hProcess, dwMilliseconds };
            var result = (uint)DynamicAPIInvoke("user32.dll", "WaitForInputIdle", typeof(Delegates.WaitForInputIdle), ref parameters);

            return result;
        }

        public static IntPtr FindWindowExA(IntPtr parentHandle, IntPtr hWndChildAfter, string className, string windowTitle)
        {
            object[] parameters = { parentHandle, hWndChildAfter, className, windowTitle };
            var result = (IntPtr)DynamicAPIInvoke("user32.dll", "FindWindowExA", typeof(Delegates.FindWindowExA), ref parameters);

            return result;
        }

        public static IntPtr SendMessageA(IntPtr hWnd, uint Msg, IntPtr wParam, ref Win32.COPYDATASTRUCT lParam)
        {
            object[] parameters = { hWnd, Msg, wParam, lParam };
            var result = (IntPtr)DynamicAPIInvoke("user32.dll", "SendMessageA", typeof(Delegates.SendMessageA), ref parameters);

            return result;
        }

        public static NTSTATUS RtlCreateUserThread(IntPtr ProcessHandle, IntPtr ThreadSecurity, bool CreateSuspended, Int32 StackZeroBits, IntPtr StackReserved, IntPtr StackCommit, IntPtr StartAddress, IntPtr Parameter, ref IntPtr ThreadHandle, IntPtr ClientId)
        {
            object[] parameters = {
                ProcessHandle,
                ThreadSecurity,
                CreateSuspended,
                StackZeroBits,
                StackReserved,
                StackCommit,
                StartAddress,
                Parameter,
                ThreadHandle,
                ClientId};

            var result = (NTSTATUS)DynamicAPIInvoke("ntdll.dll", "RtlCreateUserThread", typeof(Delegates.RtlCreateUserThread), ref parameters);

            ThreadHandle = (IntPtr)parameters[8];
            return result;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct KernelCallBackTable
        {
            public IntPtr fnCOPYDATA;
            public IntPtr fnCOPYGLOBALDATA;
            public IntPtr fnDWORD;
            public IntPtr fnNCDESTROY;
            public IntPtr fnDWORDOPTINLPMSG;
            public IntPtr fnINOUTDRAG;
            public IntPtr fnGETTEXTLENGTHS;
            public IntPtr fnINCNTOUTSTRING;
            public IntPtr fnPOUTLPINT;
            public IntPtr fnINLPCOMPAREITEMSTRUCT;
            public IntPtr fnINLPCREATESTRUCT;
            public IntPtr fnINLPDELETEITEMSTRUCT;
            public IntPtr fnINLPDRAWITEMSTRUCT;
            public IntPtr fnPOPTINLPUINT;
            public IntPtr fnPOPTINLPUINT2;
            public IntPtr fnINLPMDICREATESTRUCT;
            public IntPtr fnINOUTLPMEASUREITEMSTRUCT;
            public IntPtr fnINLPWINDOWPOS;
            public IntPtr fnINOUTLPPOINT5;
            public IntPtr fnINOUTLPSCROLLINFO;
            public IntPtr fnINOUTLPRECT;
            public IntPtr fnINOUTNCCALCSIZE;
            public IntPtr fnINOUTLPPOINT5_;
            public IntPtr fnINPAINTCLIPBRD;
            public IntPtr fnINSIZECLIPBRD;
            public IntPtr fnINDESTROYCLIPBRD;
            public IntPtr fnINSTRING;
            public IntPtr fnINSTRINGNULL;
            public IntPtr fnINDEVICECHANGE;
            public IntPtr fnPOWERBROADCAST;
            public IntPtr fnINLPUAHDRAWMENU;
            public IntPtr fnOPTOUTLPDWORDOPTOUTLPDWORD;
            public IntPtr fnOPTOUTLPDWORDOPTOUTLPDWORD_;
            public IntPtr fnOUTDWORDINDWORD;
            public IntPtr fnOUTLPRECT;
            public IntPtr fnOUTSTRING;
            public IntPtr fnPOPTINLPUINT3;
            public IntPtr fnPOUTLPINT2;
            public IntPtr fnSENTDDEMSG;
            public IntPtr fnINOUTSTYLECHANGE;
            public IntPtr fnHkINDWORD;
            public IntPtr fnHkINLPCBTACTIVATESTRUCT;
            public IntPtr fnHkINLPCBTCREATESTRUCT;
            public IntPtr fnHkINLPDEBUGHOOKSTRUCT;
            public IntPtr fnHkINLPMOUSEHOOKSTRUCTEX;
            public IntPtr fnHkINLPKBDLLHOOKSTRUCT;
            public IntPtr fnHkINLPMSLLHOOKSTRUCT;
            public IntPtr fnHkINLPMSG;
            public IntPtr fnHkINLPRECT;
            public IntPtr fnHkOPTINLPEVENTMSG;
            public IntPtr xxxClientCallDelegateThread;
            public IntPtr ClientCallDummyCallback;
            public IntPtr fnKEYBOARDCORRECTIONCALLOUT;
            public IntPtr fnOUTLPCOMBOBOXINFO;
            public IntPtr fnINLPCOMPAREITEMSTRUCT2;
            public IntPtr xxxClientCallDevCallbackCapture;
            public IntPtr xxxClientCallDitThread;
            public IntPtr xxxClientEnableMMCSS;
            public IntPtr xxxClientUpdateDpi;
            public IntPtr xxxClientExpandStringW;
            public IntPtr ClientCopyDDEIn1;
            public IntPtr ClientCopyDDEIn2;
            public IntPtr ClientCopyDDEOut1;
            public IntPtr ClientCopyDDEOut2;
            public IntPtr ClientCopyImage;
            public IntPtr ClientEventCallback;
            public IntPtr ClientFindMnemChar;
            public IntPtr ClientFreeDDEHandle;
            public IntPtr ClientFreeLibrary;
            public IntPtr ClientGetCharsetInfo;
            public IntPtr ClientGetDDEFlags;
            public IntPtr ClientGetDDEHookData;
            public IntPtr ClientGetListboxString;
            public IntPtr ClientGetMessageMPH;
            public IntPtr ClientLoadImage;
            public IntPtr ClientLoadLibrary;
            public IntPtr ClientLoadMenu;
            public IntPtr ClientLoadLocalT1Fonts;
            public IntPtr ClientPSMTextOut;
            public IntPtr ClientLpkDrawTextEx;
            public IntPtr ClientExtTextOutW;
            public IntPtr ClientGetTextExtentPointW;
            public IntPtr ClientCharToWchar;
            public IntPtr ClientAddFontResourceW;
            public IntPtr ClientThreadSetup;
            public IntPtr ClientDeliverUserApc;
            public IntPtr ClientNoMemoryPopup;
            public IntPtr ClientMonitorEnumProc;
            public IntPtr ClientCallWinEventProc;
            public IntPtr ClientWaitMessageExMPH;
            public IntPtr ClientWOWGetProcModule;
            public IntPtr ClientWOWTask16SchedNotify;
            public IntPtr ClientImmLoadLayout;
            public IntPtr ClientImmProcessKey;
            public IntPtr fnIMECONTROL;
            public IntPtr fnINWPARAMDBCSCHAR;
            public IntPtr fnGETTEXTLENGTHS2;
            public IntPtr fnINLPKDRAWSWITCHWND;
            public IntPtr ClientLoadStringW;
            public IntPtr ClientLoadOLE;
            public IntPtr ClientRegisterDragDrop;
            public IntPtr ClientRevokeDragDrop;
            public IntPtr fnINOUTMENUGETOBJECT;
            public IntPtr ClientPrinterThunk;
            public IntPtr fnOUTLPCOMBOBOXINFO2;
            public IntPtr fnOUTLPSCROLLBARINFO;
            public IntPtr fnINLPUAHDRAWMENU2;
            public IntPtr fnINLPUAHDRAWMENUITEM;
            public IntPtr fnINLPUAHDRAWMENU3;
            public IntPtr fnINOUTLPUAHMEASUREMENUITEM;
            public IntPtr fnINLPUAHDRAWMENU4;
            public IntPtr fnOUTLPTITLEBARINFOEX;
            public IntPtr fnTOUCH;
            public IntPtr fnGESTURE;
            public IntPtr fnPOPTINLPUINT4;
            public IntPtr fnPOPTINLPUINT5;
            public IntPtr xxxClientCallDefaultInputHandler;
            public IntPtr fnEMPTY;
            public IntPtr ClientRimDevCallback;
            public IntPtr xxxClientCallMinTouchHitTestingCallback;
            public IntPtr ClientCallLocalMouseHooks;
            public IntPtr xxxClientBroadcastThemeChange;
            public IntPtr xxxClientCallDevCallbackSimple;
            public IntPtr xxxClientAllocWindowClassExtraBytes;
            public IntPtr xxxClientFreeWindowClassExtraBytes;
            public IntPtr fnGETWINDOWDATA;
            public IntPtr fnINOUTSTYLECHANGE2;
            public IntPtr fnHkINLPMOUSEHOOKSTRUCTEX2;
        }

        public const uint WM_COPYDATA = 0x4A;

        public struct COPYDATASTRUCT
        {
            public IntPtr dwData;
            public int cbData;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpData;
        }
    }
}
