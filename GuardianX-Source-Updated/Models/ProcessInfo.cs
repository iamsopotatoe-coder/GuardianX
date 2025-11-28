using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32;

namespace SecureTaskManager.Models
{
    public class ProcessInfo : INotifyPropertyChanged
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public double CpuUsage { get; set; }
        public long MemoryUsage { get; set; }
        public string UserAccount { get; set; }
        public string FilePath { get; set; }
        public string CompanyName { get; set; }
        public bool IsUnsigned { get; set; }
        public bool IsHidden { get; set; }
        public bool IsStartup { get; set; }
        public string RiskLevel { get; set; }
        public string SecurityIcons { get; set; }
        public Process Process { get; set; }
        public string MalwareThreatLevel { get; set; }
        public bool IsPotentialMalware { get; set; }
        public string FileExtension { get; set; }
        public bool IsHollowed { get; set; }
        public bool IsRootkit { get; set; }
        public bool IsSuspiciousParent { get; set; }
        public int ReputationScore { get; set; }
        public System.Windows.Media.ImageSource Icon { get; set; }
        public bool HasInternetConnections { get; set; }
        public int ConnectionCount { get; set; }

        private bool isExpanded;
        public bool IsExpanded
        {
            get => isExpanded;
            set
            {
                isExpanded = value;
                OnPropertyChanged();
            }
        }

        private string processTree;
        public string ProcessTree
        {
            get => processTree;
            set
            {
                processTree = value;
                OnPropertyChanged();
            }
        }

        public string MemoryUsageMB => $"{MemoryUsage / 1024.0 / 1024.0:F1} MB";
        public string CpuUsagePercent => $"{CpuUsage:F1}%";

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class StartupInfo
    {
        public string Name { get; set; }
        public string Publisher { get; set; }
        public string Path { get; set; }
        public string StartupType { get; set; }
        public bool IsEnabled { get; set; }
        public bool IsUnsigned { get; set; }
        public string RegistryKey { get; set; }
        public bool IsMalicious { get; set; }
        public string RiskLevel { get; set; }

        public string SignedStatus => IsUnsigned ? "No" : "Yes";
    }

    public class NetworkConnection
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public bool IsSuspicious { get; set; }
        public string ThreatIndicator { get; set; }
    }
}
