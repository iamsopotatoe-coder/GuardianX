using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SecureTaskManager.Services
{
    public static class ProcessExtensions
    {
        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            out int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        public static Process GetParentProcess(Process process)
        {
            try
            {
                var pbi = new PROCESS_BASIC_INFORMATION();
                int returnLength;
                int status = NtQueryInformationProcess(
                    process.Handle,
                    0,
                    ref pbi,
                    Marshal.SizeOf(pbi),
                    out returnLength);

                if (status != 0)
                    return null;

                return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
            }
            catch
            {
                return null;
            }
        }
    }
}
