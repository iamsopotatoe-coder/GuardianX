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
using SecureTaskManager.Models;

namespace SecureTaskManager.Services
{
    public class ProcessAnalyzer
    {
        private Dictionary<int, PerformanceCounter> cpuCounters = new Dictionary<int, PerformanceCounter>();
        private Dictionary<int, DateTime> lastCpuCheck = new Dictionary<int, DateTime>();
        private Dictionary<int, TimeSpan> lastCpuTime = new Dictionary<int, TimeSpan>();
        private MalwareSignatureDetector malwareDetector = new MalwareSignatureDetector();

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, IntPtr pgActionID, IntPtr pWVTData);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        private HashSet<uint> visibleProcessIds = new HashSet<uint>();

        public List<ProcessInfo> GetAllProcesses()
        {
            UpdateVisibleProcesses();
            var processes = Process.GetProcesses();
            var processInfos = new List<ProcessInfo>();

            var results = new System.Collections.Concurrent.ConcurrentBag<ProcessInfo>();
            
            Parallel.ForEach(processes, new ParallelOptions { MaxDegreeOfParallelism = 8 }, process =>
            {
                try
                {
                    var info = CreateProcessInfo(process);
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

        private ProcessInfo CreateProcessInfo(Process process)
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
                
                var malwareSignature = malwareDetector.AnalyzeFile(info.FilePath);
                info.MalwareThreatLevel = malwareSignature.ThreatLevel;
                info.IsPotentialMalware = malwareSignature.IsMalware;
                
                info.RiskLevel = DetermineRiskLevel(info, malwareSignature);
                info.SecurityIcons = GetSecurityIcons(info);
            }
            catch
            {
            }

            return info;
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
                X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                if (cert == null)
                    return false;

                X509Certificate2 cert2 = new X509Certificate2(cert);
                cert.Dispose();

                if (cert2.NotAfter < DateTime.Now || cert2.NotBefore > DateTime.Now)
                {
                    cert2.Dispose();
                    return false;
                }

                bool isValid = false;
                try
                {
                    X509Chain chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
                    isValid = chain.Build(cert2);
                    chain.Reset();
                }
                catch
                {
                    isValid = true;
                }

                cert2.Dispose();
                return isValid;
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return false;
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

            var startupPaths = GetStartupPaths();
            return startupPaths.Any(path => 
                filePath.Equals(path, StringComparison.OrdinalIgnoreCase));
        }

        private HashSet<string> GetStartupPaths()
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
                    AddRegistryStartupPaths(Registry.LocalMachine, keyPath, paths);
                    AddRegistryStartupPaths(Registry.CurrentUser, keyPath, paths);
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

        private void AddRegistryStartupPaths(RegistryKey root, string keyPath, HashSet<string> paths)
        {
            try
            {
                using (var key = root.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            var value = key.GetValue(valueName)?.ToString();
                            if (!string.IsNullOrEmpty(value))
                            {
                                var path = ExtractPathFromCommand(value);
                                if (!string.IsNullOrEmpty(path))
                                    paths.Add(path);
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private string ExtractPathFromCommand(string command)
        {
            if (string.IsNullOrEmpty(command))
                return null;

            command = command.Trim();
            if (command.StartsWith("\""))
            {
                int endQuote = command.IndexOf("\"", 1);
                if (endQuote > 0)
                    return command.Substring(1, endQuote - 1);
            }

            var parts = command.Split(' ');
            return parts[0];
        }

        private string DetermineRiskLevel(ProcessInfo info, MalwareSignature malwareSignature = null)
        {
            if (string.IsNullOrEmpty(info.FilePath) || info.FilePath == "[System Process]")
                return "Green";

            if (malwareSignature != null && malwareSignature.IsMalware)
                return "Red";

            int riskScore = 0;
            
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
            
            if (info.IsPotentialMalware)
                icons.Add("⚠");
            
            if (info.IsUnsigned)
                icons.Add("U");
            
            if (info.IsHidden)
                icons.Add("H");
            
            if (info.IsStartup)
                icons.Add("S");

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
