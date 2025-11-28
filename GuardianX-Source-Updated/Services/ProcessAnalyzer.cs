using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SecureTaskManager.Models;

namespace SecureTaskManager.Services
{
    public class ProcessAnalyzer
    {
        private Dictionary<int, PerformanceCounter> cpuCounters = new Dictionary<int, PerformanceCounter>();
        private Dictionary<int, DateTime> lastCpuCheck = new Dictionary<int, DateTime>();
        private Dictionary<int, TimeSpan> lastCpuTime = new Dictionary<int, TimeSpan>();
        private MalwareSignatureDetector malwareDetector = new MalwareSignatureDetector();

        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes, ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct SHFILEINFO
        {
            public IntPtr hIcon;
            public int iIcon;
            public uint dwAttributes;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szDisplayName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
            public string szTypeName;
        }

        private const uint SHGFI_ICON = 0x100;
        private const uint SHGFI_LARGEICON = 0x0;
        private const uint SHGFI_SMALLICON = 0x1;
        private const uint SHGFI_USEFILEATTRIBUTES = 0x10;

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, WinTrustData pWVTData);

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        class WinTrustData
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;

            public WinTrustData(IntPtr _pFile)
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustData));
                pPolicyCallbackData = IntPtr.Zero;
                pSIPClientData = IntPtr.Zero;
                dwUIChoice = 2; // WTD_UI_NONE
                fdwRevocationChecks = 0;
                dwUnionChoice = 1; // WTD_CHOICE_FILE
                pFile = _pFile;
                dwStateAction = 0;
                hWVTStateData = IntPtr.Zero;
                pwszURLReference = IntPtr.Zero;
                dwProvFlags = 0x00000010; // WTD_SAFER_FLAG
                dwUIContext = 0;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        class WinTrustFileInfo
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;

            public WinTrustFileInfo(string _filePath)
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo));
                pcwszFilePath = _filePath;
                hFile = IntPtr.Zero;
                pgKnownSubject = IntPtr.Zero;
            }
        }

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        private HashSet<uint> visibleProcessIds = new HashSet<uint>();

        public List<ProcessInfo> GetAllProcesses(HashSet<int> pidsWithInternet = null)
        {
            UpdateVisibleProcesses();
            var processes = Process.GetProcesses();
            var processInfos = new List<ProcessInfo>();

            var results = new System.Collections.Concurrent.ConcurrentBag<ProcessInfo>();
            
            Parallel.ForEach(processes, new ParallelOptions { MaxDegreeOfParallelism = 8 }, process =>
            {
                try
                {
                    var info = CreateProcessInfo(process, pidsWithInternet);
                    if (info != null)
                        results.Add(info);
                }
                catch
                {
                    try
                    {
                        var basicInfo = new ProcessInfo
                        {
                            ProcessId = process.Id,
                            ProcessName = process.ProcessName,
                            Process = process,
                            MemoryUsage = 0,
                            FilePath = "[System Process]",
                            CompanyName = "System",
                            RiskLevel = "Green",
                            SecurityIcons = ""
                        };
                        results.Add(basicInfo);
                    }
                    catch { }
                }
            });

            return results.OrderBy(p => p.RiskLevel == "Red" ? 0 : p.RiskLevel == "Orange" ? 1 : p.RiskLevel == "Yellow" ? 2 : 3)
                         .ThenBy(p => p.ProcessName).ToList();
        }

        private ProcessInfo CreateProcessInfo(Process process, HashSet<int> pidsWithInternet)
        {
            var info = new ProcessInfo
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                Process = process
            };

            try
            {
                info.MemoryUsage = process.WorkingSet64;
                info.FilePath = GetProcessPath(process);
                info.CompanyName = GetCompanyName(process);
                info.UserAccount = GetProcessUser(process);
                info.CpuUsage = GetCpuUsage(process);
                
                info.IsUnsigned = !IsDigitallySigned(info.FilePath);
                info.IsHidden = IsProcessHidden(process);
                info.IsStartup = IsStartupProcess(info.FilePath);
                info.FileExtension = !string.IsNullOrEmpty(info.FilePath) ? Path.GetExtension(info.FilePath) : "";
                
                info.Icon = GetProcessIcon(info.FilePath);

                info.HasInternetConnections = pidsWithInternet != null && pidsWithInternet.Contains(process.Id);

                info.IsHollowed = IsProcessHollowed(process, info);
                info.IsRootkit = IsRootkit(process, info);
                info.IsSuspiciousParent = IsSuspiciousParent(process);

                var malwareSignature = malwareDetector.AnalyzeFile(info.FilePath);
                info.MalwareThreatLevel = malwareSignature.ThreatLevel;
                info.IsPotentialMalware = malwareSignature.IsMalware;

                info.RiskLevel = DetermineRiskLevel(info, malwareSignature);
                info.ReputationScore = CalculateReputation(info, malwareSignature);
                info.SecurityIcons = GetSecurityIcons(info);
            }
            catch
            {
            }

            return info;
        }

        private int CalculateReputation(ProcessInfo info, MalwareSignature malwareSignature)
        {
            int score = 100;

            if (info.IsRootkit) score -= 50;
            if (info.IsHollowed) score -= 40;
            if (info.IsSuspiciousParent) score -= 30;
            if (info.IsPotentialMalware) score -= 60;
            if (info.IsUnsigned) score -= 20;
            if (info.IsHidden) score -= 20;
            if (IsSuspiciousLocation(info.FilePath)) score -= 25;
            if (string.IsNullOrEmpty(info.CompanyName) && info.IsUnsigned) score -= 15;
            if (IsSuspiciousProcessName(info.ProcessName)) score -= 30;

            if (info.FilePath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.System), StringComparison.OrdinalIgnoreCase) && !info.IsUnsigned)
                score += 10;

            if (info.MemoryUsage > 500 * 1024 * 1024 && info.IsUnsigned) score -= 10;

            return Math.Max(0, Math.Min(100, score));
        }

        private ImageSource GetProcessIcon(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return null;

            try
            {
                SHFILEINFO shinfo = new SHFILEINFO();
                IntPtr hImg = SHGetFileInfo(filePath, 0, ref shinfo, (uint)Marshal.SizeOf(shinfo), SHGFI_ICON | SHGFI_SMALLICON);

                if (shinfo.hIcon != IntPtr.Zero)
                {
                    ImageSource icon = Imaging.CreateBitmapSourceFromHIcon(
                        shinfo.hIcon,
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromEmptyOptions());
                    
                    // Freeze to make it cross-thread accessible
                    icon.Freeze();
                    
                    // Cleanup
                    DestroyIcon(shinfo.hIcon);
                    
                    return icon;
                }
            }
            catch { }
            return null;
        }

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool DestroyIcon(IntPtr hIcon);

        private bool IsProcessHollowed(Process process, ProcessInfo info)
        {
            if (info.HasInternetConnections)
            {
                var offlineSystemProcesses = new[] { "notepad", "calc", "taskmgr", "mspaint", "cmd", "powershell" };
                if (offlineSystemProcesses.Contains(process.ProcessName.ToLower()))
                    return true;
            }

            try
            {
                var parent = ProcessExtensions.GetParentProcess(process);
                if (parent != null)
                {
                    if (process.ProcessName.Equals("svchost", StringComparison.OrdinalIgnoreCase) &&
                        !parent.ProcessName.Equals("services", StringComparison.OrdinalIgnoreCase))
                        return true;

                    if (process.ProcessName.Equals("lsass", StringComparison.OrdinalIgnoreCase) &&
                        !parent.ProcessName.Equals("wininit", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { }

            return false;
        }

        private bool IsRootkit(Process process, ProcessInfo info)
        {
            if (info.IsHidden)
            {
                if (!info.IsUnsigned)
                    return false;

                var criticalProcesses = new[] { "csrss", "smss", "wininit", "services", "lsass", "winlogon" };
                if (criticalProcesses.Contains(process.ProcessName.ToLower()))
                    return true;
            }

            var rootkitNames = new[] { "fu", "hxdef", "haktek", "elite", "afx", "r77" };
            if (rootkitNames.Any(n => process.ProcessName.ToLower().Contains(n)))
                return true;

            if (!string.IsNullOrEmpty(info.FilePath) && !File.Exists(info.FilePath) && info.FilePath != "[System Process]")
                return true;

            return false;
        }

        private bool IsSuspiciousParent(Process process)
        {
            try
            {
                var parent = ProcessExtensions.GetParentProcess(process);
                if (parent == null) return false;

                string parentName = parent.ProcessName.ToLower();
                string processName = process.ProcessName.ToLower();

                if (processName == "svchost" && parentName != "services") return true;
                if (processName == "lsass" && parentName != "wininit") return true;
                if (processName == "services" && parentName != "wininit") return true;
                if (processName == "csrss" && parentName != "smss" && parentName != "csrss") return true;
                if (processName == "wininit" && parentName != "smss") return true;
                if (processName == "winlogon" && parentName != "smss") return true;
                if (processName == "smss" && parentName != "system") return true;

                if (parentName == "explorer")
                {
                    var systemServices = new[] { "svchost", "lsass", "services", "wininit", "smss", "csrss", "winlogon" };
                    if (systemServices.Contains(processName)) return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "";
            }
            catch
            {
                try
                {
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {process.Id}"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            return obj["ExecutablePath"]?.ToString() ?? "";
                        }
                    }
                }
                catch
                {
                    // Ignored
                }
            }
            return "";
        }

        private string GetCompanyName(Process process)
        {
            try
            {
                return process.MainModule?.FileVersionInfo?.CompanyName ?? "";
            }
            catch
            {
                return "";
            }
        }

        private string GetProcessUser(Process process)
        {
            return "";
        }

        private double GetCpuUsage(Process process)
        {
            return 0;
        }

        private bool IsDigitallySigned(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return false;

            try
            {
                WinTrustFileInfo winTrustFileInfo = new WinTrustFileInfo(filePath);
                IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(winTrustFileInfo, pFileInfo, false);

                WinTrustData winTrustData = new WinTrustData(pFileInfo);
                
                int result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, winTrustData);

                Marshal.FreeHGlobal(pFileInfo);

                return result == 0;
            }
            catch
            {
                return false;
            }
        }

        private void UpdateVisibleProcesses()
        {
            visibleProcessIds.Clear();
            EnumWindows((hWnd, lParam) =>
            {
                if (IsWindowVisible(hWnd))
                {
                    GetWindowThreadProcessId(hWnd, out uint processId);
                    if (processId != 0)
                        visibleProcessIds.Add(processId);
                }
                return true;
            }, IntPtr.Zero);
        }

        private bool IsProcessHidden(Process process)
        {
            try
            {
                if (process.MainWindowHandle != IntPtr.Zero)
                    return false;

                if (process.ProcessName.EndsWith("svc", StringComparison.OrdinalIgnoreCase) ||
                    process.SessionId == 0)
                    return false;

                return !visibleProcessIds.Contains((uint)process.Id) && 
                       process.WorkingSet64 > 1024 * 1024;
            }
            catch
            {
                return false;
            }
        }

        private bool IsStartupProcess(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return false;

            var startupPaths = _gsp();
            return startupPaths.Any(path =>
                filePath.Equals(path, StringComparison.OrdinalIgnoreCase));
        }

        private HashSet<string> _gsp()
        {
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                var runKeys = new[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                };

                foreach (var keyPath in runKeys)
                {
                    _arp(Registry.LocalMachine, keyPath, paths);
                    _arp(Registry.CurrentUser, keyPath, paths);
                }

                var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(startupFolder))
                {
                    foreach (var file in Directory.GetFiles(startupFolder, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        paths.Add(file);
                    }
                }
            }
            catch { }

            return paths;
        }

        private void _arp(RegistryKey r, string kp, HashSet<string> p)
        {
            try
            {
                using (var k = r.OpenSubKey(kp))
                {
                    if (k != null)
                    {
                        foreach (var vn in k.GetValueNames())
                        {
                            var v = k.GetValue(vn)?.ToString();
                            if (!string.IsNullOrEmpty(v))
                            {
                                var pa = _ep(v);
                                if (!string.IsNullOrEmpty(pa))
                                    p.Add(pa);
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private string _ep(string c)
        {
            if (string.IsNullOrEmpty(c))
                return null;

            c = c.Trim();
            if (c.StartsWith("\""))
            {
                int eq = c.IndexOf("\"", 1);
                if (eq > 0)
                    return c.Substring(1, eq - 1);
            }

            var p = c.Split(' ');
            return p[0];
        }

        private string DetermineRiskLevel(ProcessInfo info, MalwareSignature malwareSignature = null)
        {
            if (string.IsNullOrEmpty(info.FilePath) || info.FilePath == "[System Process]")
                return "Green";

            if (malwareSignature != null && malwareSignature.IsMalware)
                return "Red";

            int riskScore = 0;
            
            if (info.IsRootkit) riskScore += 5;
            if (info.IsHollowed) riskScore += 5;
            if (info.IsSuspiciousParent) riskScore += 4;

            if (info.IsUnsigned) riskScore += 3;
            if (info.IsHidden) riskScore += 3;
            
            bool isSuspiciousLocation = IsSuspiciousLocation(info.FilePath);
            if (isSuspiciousLocation) riskScore += 4;
            
            bool noCompany = string.IsNullOrEmpty(info.CompanyName);
            if (noCompany && info.IsUnsigned) riskScore += 2;
            
            bool highMemory = info.MemoryUsage > 500 * 1024 * 1024;
            if (highMemory && info.IsUnsigned) riskScore += 2;
            
            bool suspiciousName = IsSuspiciousProcessName(info.ProcessName);
            if (suspiciousName) riskScore += 3;
            
            if (riskScore >= 7)
                return "Red";
            else if (riskScore >= 4)
                return "Orange";
            else if (riskScore >= 2)
                return "Yellow";
            
            return "Green";
        }

        private bool IsSuspiciousProcessName(string processName)
        {
            if (string.IsNullOrEmpty(processName))
                return false;
                
            var suspiciousPatterns = new[]
            {
                "svchost32", "csrss32", "lsass32", "winlogon32",
                "svch0st", "iexpl0re", "chr0me",
                "keygen", "crack", "patch", "loader",
                "miner", "cryptonight", "xmrig",
                "trojan", "backdoor", "rootkit", "keylog",
                "rat", "stealer", "inject", "payload"
            };
            
            return suspiciousPatterns.Any(pattern => 
                processName.Contains(pattern, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsSuspiciousLocation(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return false;

            var suspiciousLocations = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.InternetCache),
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Temp",
                "\\AppData\\Local\\Temp",
                "\\AppData\\Roaming",
                "\\Downloads",
                "\\Users\\Public"
            };

            return suspiciousLocations.Any(loc => 
                filePath.Contains(loc, StringComparison.OrdinalIgnoreCase));
        }

        private string GetSecurityIcons(ProcessInfo info)
        {
            var icons = new List<string>();
            
            if (info.IsRootkit)
                icons.Add("ROOTKIT");

            if (info.IsHollowed)
                icons.Add("HOLLOW");

            if (info.IsSuspiciousParent)
                icons.Add("PARENT");

            if (info.IsPotentialMalware)
                icons.Add("⚠");
            
            if (info.IsUnsigned)
                icons.Add("U");
            
            if (info.IsHidden)
                icons.Add("H");
            
            if (info.IsStartup)
                icons.Add("S");

            if (info.HasInternetConnections)
                icons.Add("NET");

            return icons.Count > 0 ? string.Join(" ", icons) : "-";
        }

        public void TerminateProcess(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                process.Kill();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to terminate process: {ex.Message}");
            }
        }

        public void TerminateProcessTree(int processId)
        {
            try
            {
                var childProcesses = GetChildProcesses(processId);
                foreach (var childPid in childProcesses)
                {
                    TerminateProcessTree(childPid);
                }
                TerminateProcess(processId);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to terminate process tree: {ex.Message}");
            }
        }

        private List<int> GetChildProcesses(int parentId)
        {
            var children = new List<int>();
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId = {parentId}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        children.Add(Convert.ToInt32(obj["ProcessId"]));
                    }
                }
            }
            catch { }
            return children;
        }

        public string GetDetailedProcessInfo(ProcessInfo info)
        {
            var sb = new StringBuilder();
            try
            {
                var process = Process.GetProcessById(info.ProcessId);
                
                sb.AppendLine($"Process Name: {info.ProcessName}");
                sb.AppendLine($"Process ID: {info.ProcessId}");
                sb.AppendLine($"File Path: {info.FilePath}");
                sb.AppendLine($"Company: {info.CompanyName}");
                sb.AppendLine($"User Account: {info.UserAccount}");
                sb.AppendLine($"Memory Usage: {info.MemoryUsageMB}");
                sb.AppendLine($"CPU Usage: {info.CpuUsagePercent}");
                sb.AppendLine($"Started: {process.StartTime:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"Threads: {process.Threads.Count}");
                sb.AppendLine();
                
                sb.AppendLine("Security Status:");
                sb.AppendLine($"Digital Signature: {(info.IsUnsigned ? "NOT SIGNED" : "Verified")}");
                sb.AppendLine($"Hidden Process: {(info.IsHidden ? "YES" : "No")}");
                sb.AppendLine($"Suspicious Parent: {(info.IsSuspiciousParent ? "YES" : "No")}");
                sb.AppendLine($"Startup Item: {(info.IsStartup ? "YES" : "No")}");
                sb.AppendLine($"Risk Level: {info.RiskLevel}");
                sb.AppendLine();
                
                // Add malware analysis
                if (info.IsPotentialMalware || info.MalwareThreatLevel != "None")
                {
                    sb.AppendLine("⚠ MALWARE ANALYSIS:");
                    var malwareSignature = malwareDetector.AnalyzeFile(info.FilePath);
                    sb.AppendLine(malwareSignature.GetSummary());
                    sb.AppendLine();
                }

                try
                {
                    sb.AppendLine($"Command Line:");
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {info.ProcessId}"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            sb.AppendLine(obj["CommandLine"]?.ToString() ?? "N/A");
                        }
                    }
                    sb.AppendLine();
                }
                catch { }

                try
                {
                    sb.AppendLine("Loaded Modules:");
                    int count = 0;
                    foreach (ProcessModule module in process.Modules)
                    {
                        sb.AppendLine($"  {module.FileName}");
                        count++;
                        if (count >= 20)
                        {
                            sb.AppendLine($"  ... and {process.Modules.Count - count} more");
                            break;
                        }
                    }
                }
                catch { }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"Error getting detailed info: {ex.Message}");
            }

            return sb.ToString();
        }
    }
}
