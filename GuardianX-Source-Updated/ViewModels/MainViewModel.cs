using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using SecureTaskManager.Models;
using SecureTaskManager.Services;

namespace SecureTaskManager.ViewModels
{
    public class TabSwitchEventArgs : EventArgs
    {
        public string TabName { get; set; }
        public object HighlightItem { get; set; }
    }

    public class MainViewModel : INotifyPropertyChanged
    {
        public event EventHandler<TabSwitchEventArgs> TabSwitchRequested;
        private readonly ProcessAnalyzer processAnalyzer;
        private readonly StartupManager startupManager;
        private readonly NetworkAnalyzer networkAnalyzer;
        private readonly DispatcherTimer refreshTimer;
        private HashSet<string> whitelist = new HashSet<string>();

        public ObservableCollection<ProcessInfo> Processes { get; set; }
        public ObservableCollection<StartupInfo> StartupItems { get; set; }
        public ObservableCollection<NetworkConnection> NetworkConnections { get; set; }

        private ProcessInfo selectedProcess;
        public ProcessInfo SelectedProcess
        {
            get => selectedProcess;
            set
            {
                selectedProcess = value;
                OnPropertyChanged();
                UpdateDetailedInfo();
            }
        }

        private string detailedInfo;
        public string DetailedInfo
        {
            get => detailedInfo;
            set
            {
                detailedInfo = value;
                OnPropertyChanged();
            }
        }

        private string startupInfo;
        public string StartupInfo
        {
            get => startupInfo;
            set
            {
                startupInfo = value;
                OnPropertyChanged();
            }
        }

        private string processTreeInfo;
        public string ProcessTreeInfo
        {
            get => processTreeInfo;
            set
            {
                processTreeInfo = value;
                OnPropertyChanged();
            }
        }

        private StartupInfo selectedStartupItem;
        public StartupInfo SelectedStartupItem
        {
            get => selectedStartupItem;
            set
            {
                selectedStartupItem = value;
                OnPropertyChanged();
            }
        }

        private string searchText;
        public string SearchText
        {
            get => searchText;
            set
            {
                searchText = value;
                OnPropertyChanged();
                ApplyFilter();
            }
        }

        private string statusText;
        public string StatusText
        {
            get => statusText;
            set
            {
                statusText = value;
                OnPropertyChanged();
            }
        }

        public ICommand RefreshCommand { get; set; }
        public ICommand EndProcessCommand { get; set; }
        public ICommand EndProcessTreeCommand { get; set; }
        public ICommand SearchOnlineCommand { get; set; }
        public ICommand ShowFileLocationCommand { get; set; }
        public ICommand DeleteApplicationCommand { get; set; }
        public ICommand ShowPropertiesCommand { get; set; }
        public ICommand ToggleProcessTreeCommand { get; set; }
        public ICommand GoToStartupCommand { get; set; }
        public ICommand AddToWhitelistCommand { get; set; }
        public ICommand DisableStartupCommand { get; set; }
        public ICommand DeleteStartupCommand { get; set; }
        public ICommand ShowStartupFileLocationCommand { get; set; }
        public ICommand ExportCommand { get; set; }
        public ICommand BackToProcessesCommand { get; set; }
        public ICommand TerminateConnectionCommand { get; set; }

        private NetworkConnection selectedNetworkConnection;
        public NetworkConnection SelectedNetworkConnection
        {
            get => selectedNetworkConnection;
            set
            {
                selectedNetworkConnection = value;
                OnPropertyChanged();
            }
        }

        public MainViewModel()
        {
            processAnalyzer = new ProcessAnalyzer();
            startupManager = new StartupManager();
            networkAnalyzer = new NetworkAnalyzer();

            Processes = new ObservableCollection<ProcessInfo>();
            StartupItems = new ObservableCollection<StartupInfo>();
            NetworkConnections = new ObservableCollection<NetworkConnection>();

            StartupInfo = "Select a process to see if it runs at startup.";

            InitializeCommands();
            LoadData();

            refreshTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5)
            };
            refreshTimer.Tick += (s, e) => Task.Run(() => RefreshProcesses());
            refreshTimer.Start();
        }

        private void InitializeCommands()
        {
            RefreshCommand = new RelayCommand(async _ => await RefreshAllAsync());
            EndProcessCommand = new RelayCommand(EndProcess, _ => SelectedProcess != null);
            EndProcessTreeCommand = new RelayCommand(EndProcessTree, _ => SelectedProcess != null);
            SearchOnlineCommand = new RelayCommand(SearchOnline, _ => SelectedProcess != null);
            ShowFileLocationCommand = new RelayCommand(ShowFileLocation, _ => SelectedProcess != null && !string.IsNullOrEmpty(SelectedProcess.FilePath));
            DeleteApplicationCommand = new RelayCommand(DeleteApplication, _ => SelectedProcess != null && !string.IsNullOrEmpty(SelectedProcess.FilePath));
            ShowPropertiesCommand = new RelayCommand(ShowProperties, _ => SelectedProcess != null);
            ToggleProcessTreeCommand = new RelayCommand(ToggleProcessTree, _ => SelectedProcess != null);
            GoToStartupCommand = new RelayCommand(GoToStartup, _ => SelectedProcess != null && SelectedProcess.IsStartup);
            AddToWhitelistCommand = new RelayCommand(AddToWhitelist, _ => SelectedProcess != null);
            DisableStartupCommand = new RelayCommand(DisableStartup);
            DeleteStartupCommand = new RelayCommand(DeleteStartup);
            ShowStartupFileLocationCommand = new RelayCommand(ShowStartupFileLocation);
            ExportCommand = new RelayCommand(ExportToCSV);
            BackToProcessesCommand = new RelayCommand(_ => TabSwitchRequested?.Invoke(this, new TabSwitchEventArgs { TabName = "Processes" }));
            TerminateConnectionCommand = new RelayCommand(TerminateConnection);
        }

        private void LoadData()
        {
            Task.Run(() =>
            {
                RefreshProcesses();
                RefreshStartupItems();
                RefreshNetworkConnections();
            });
        }

        private async Task RefreshAllAsync()
        {
            await Task.Run(() =>
            {
                RefreshProcesses();
                RefreshStartupItems();
                RefreshNetworkConnections();
            });
        }

        private void RefreshProcesses()
        {
            try
            {
                // Get active connections for hollowed process detection
                var connections = networkAnalyzer.GetAllConnections();
                var pidsWithInternet = new HashSet<int>(connections.Select(c => c.ProcessId));

                var processes = processAnalyzer.GetAllProcesses(pidsWithInternet);
                var filteredProcesses = processes.Where(p => !whitelist.Contains(p.ProcessName)).ToList();
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                    // Update existing items instead of clearing
                    var existingPids = new HashSet<int>(Processes.Select(p => p.ProcessId));
                    var newPids = new HashSet<int>(filteredProcesses.Select(p => p.ProcessId));
                    
                    // Remove dead processes
                    for (int i = Processes.Count - 1; i >= 0; i--)
                    {
                        if (!newPids.Contains(Processes[i].ProcessId))
                            Processes.RemoveAt(i);
                    }
                    
                    // Add new processes
                    foreach (var proc in filteredProcesses)
                    {
                        if (!existingPids.Contains(proc.ProcessId))
                            Processes.Add(proc);
                    }
                    
                    UpdateStatus();
                });
            }
            catch (Exception ex)
            {
                Application.Current.Dispatcher.Invoke(() => 
                {
                    StatusText = $"Error: {ex.Message}";
                });
            }
        }

        private void RefreshStartupItems()
        {
            try
            {
                var items = startupManager.GetAllStartupItems();
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                    StartupItems.Clear();
                    foreach (var item in items)
                    {
                        StartupItems.Add(item);
                    }
                });
            }
            catch { }
        }

        private void RefreshNetworkConnections()
        {
            try
            {
                var connections = networkAnalyzer.GetAllConnections();
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                    NetworkConnections.Clear();
                    foreach (var conn in connections)
                    {
                        NetworkConnections.Add(conn);
                    }
                });
            }
            catch { }
        }

        private void UpdateDetailedInfo()
        {
            if (SelectedProcess == null)
            {
                DetailedInfo = "Select a process from the Processes tab to view its properties.";
                StartupInfo = "Select a process to see if it runs at startup.";
                return;
            }

            Task.Run(() =>
            {
                var info = processAnalyzer.GetDetailedProcessInfo(SelectedProcess);
                Application.Current.Dispatcher.Invoke(() => DetailedInfo = info);

                // Update startup info
                var isStartup = SelectedProcess.IsStartup;
                var startupText = isStartup 
                    ? $"⚠ This process runs at STARTUP\n\nProcess: {SelectedProcess.ProcessName}\nPath: {SelectedProcess.FilePath}\n\nCheck the Startup tab to manage startup items."
                    : $"✓ This process does NOT run at startup\n\nProcess: {SelectedProcess.ProcessName}";
                Application.Current.Dispatcher.Invoke(() => StartupInfo = startupText);
            });
        }

        private void ApplyFilter()
        {
            var view = CollectionViewSource.GetDefaultView(Processes);
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                view.Filter = null;
            }
            else
            {
                view.Filter = obj =>
                {
                    var proc = obj as ProcessInfo;
                    return proc.ProcessName.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                           proc.FilePath.Contains(SearchText, StringComparison.OrdinalIgnoreCase);
                };
            }
        }

        private void UpdateStatus()
        {
            var totalCpu = Processes.Sum(p => p.CpuUsage);
            var totalMem = Processes.Sum(p => p.MemoryUsage) / 1024.0 / 1024.0 / 1024.0;
            StatusText = $"Processes: {Processes.Count} | Total CPU: {totalCpu:F1}% | Total Memory: {totalMem:F2} GB";
        }

        private void EndProcess(object parameter)
        {
            if (SelectedProcess == null) return;

            var criticalProcesses = new[] { "csrss", "smss", "wininit", "services", "lsass", "winlogon" };
            if (criticalProcesses.Contains(SelectedProcess.ProcessName.ToLower()))
            {
                MessageBox.Show("Cannot terminate critical system process!", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var result = MessageBox.Show($"Are you sure you want to end process '{SelectedProcess.ProcessName}' (PID: {SelectedProcess.ProcessId})?",
                "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    processAnalyzer.TerminateProcess(SelectedProcess.ProcessId);
                    RefreshProcesses();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void EndProcessTree(object parameter)
        {
            if (SelectedProcess == null) return;

            var result = MessageBox.Show($"Are you sure you want to end process tree for '{SelectedProcess.ProcessName}' (PID: {SelectedProcess.ProcessId})?",
                "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    processAnalyzer.TerminateProcessTree(SelectedProcess.ProcessId);
                    RefreshProcesses();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void SearchOnline(object parameter)
        {
            if (SelectedProcess == null) return;

            try
            {
                // Include file extension in search for better results
                var searchTerm = SelectedProcess.ProcessName;
                if (!string.IsNullOrEmpty(SelectedProcess.FileExtension))
                {
                    searchTerm += SelectedProcess.FileExtension;
                }
                searchTerm += " is it safe";
                
                var searchUrl = $"https://www.google.com/search?q={Uri.EscapeDataString(searchTerm)}";
                Process.Start(new ProcessStartInfo(searchUrl) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowFileLocation(object parameter)
        {
            if (SelectedProcess == null || string.IsNullOrEmpty(SelectedProcess.FilePath)) return;

            try
            {
                if (File.Exists(SelectedProcess.FilePath))
                {
                    Process.Start("explorer.exe", $"/select,\"{SelectedProcess.FilePath}\"");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DeleteApplication(object parameter)
        {
            if (SelectedProcess == null || string.IsNullOrEmpty(SelectedProcess.FilePath)) return;

            var result = MessageBox.Show($"Are you sure you want to DELETE the executable?\n\n{SelectedProcess.FilePath}\n\nThis action cannot be undone!",
                "Confirm Delete", MessageBoxButton.YesNo, MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    processAnalyzer.TerminateProcess(SelectedProcess.ProcessId);
                    Thread.Sleep(500);
                    
                    if (File.Exists(SelectedProcess.FilePath))
                    {
                        File.Delete(SelectedProcess.FilePath);
                        MessageBox.Show("Application deleted successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                        RefreshProcesses();
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ShowProperties(object parameter)
        {
            if (SelectedProcess == null) return;
            UpdateDetailedInfo();
            TabSwitchRequested?.Invoke(this, new TabSwitchEventArgs { TabName = "Properties" });
        }

        private void ToggleProcessTree(object parameter)
        {
            if (SelectedProcess == null) return;
            
            if (string.IsNullOrEmpty(SelectedProcess.ProcessTree))
            {
                Task.Run(() =>
                {
                    var treeInfo = BuildProcessTree(SelectedProcess.ProcessId);
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        SelectedProcess.ProcessTree = treeInfo;
                        SelectedProcess.IsExpanded = true;
                        OnPropertyChanged(nameof(Processes));
                    });
                });
            }
            else
            {
                SelectedProcess.ProcessTree = "";
                SelectedProcess.IsExpanded = false;
            }
        }

        private string BuildProcessTree(int processId, string indent = "", bool isLast = true)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                var sb = new System.Text.StringBuilder();
                
                sb.AppendLine($"{indent}{(isLast ? "└─" : "├─")} {process.ProcessName} (PID: {processId})");
                
                var children = GetChildProcesses(processId);
                var newIndent = indent + (isLast ? "   " : "│  ");
                
                for (int i = 0; i < children.Count; i++)
                {
                    sb.Append(BuildProcessTree(children[i], newIndent, i == children.Count - 1));
                }
                
                return sb.ToString();
            }
            catch
            {
                return $"{indent}{(isLast ? "└─" : "├─")} [Process terminated]\n";
            }
        }

        private List<int> GetChildProcesses(int parentId)
        {
            var children = new List<int>();
            try
            {
                var allProcesses = Process.GetProcesses();
                foreach (var proc in allProcesses)
                {
                    try
                    {
                        var parentProc = ProcessExtensions.GetParentProcess(proc);
                        if (parentProc != null && parentProc.Id == parentId)
                        {
                            children.Add(proc.Id);
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return children;
        }

        private void GoToStartup(object parameter)
        {
            if (SelectedProcess == null || !SelectedProcess.IsStartup) return;
            
            // Refresh startup items first to ensure we have latest data
            RefreshStartupItems();
            
            // Give UI time to update
            Application.Current.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Render);
            
            // Find the startup item that matches this process
            var startupItem = StartupItems.FirstOrDefault(s => 
                !string.IsNullOrEmpty(s.Path) && !string.IsNullOrEmpty(SelectedProcess.FilePath) &&
                (s.Path.Equals(SelectedProcess.FilePath, StringComparison.OrdinalIgnoreCase) ||
                 Path.GetFileNameWithoutExtension(s.Path).Equals(SelectedProcess.ProcessName, StringComparison.OrdinalIgnoreCase)));
            
            TabSwitchRequested?.Invoke(this, new TabSwitchEventArgs 
            { 
                TabName = "Startup",
                HighlightItem = startupItem
            });
        }

        private void AddToWhitelist(object parameter)
        {
            if (SelectedProcess == null) return;
            whitelist.Add(SelectedProcess.ProcessName);
            RefreshProcesses();
            MessageBox.Show($"'{SelectedProcess.ProcessName}' added to whitelist.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void DisableStartup(object parameter)
        {
            var item = parameter as StartupInfo;
            if (item == null) return;

            var result = MessageBox.Show($"Disable startup item: {item.Name}?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    startupManager.DisableStartupItem(item);
                    RefreshStartupItems();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void DeleteStartup(object parameter)
        {
            var item = parameter as StartupInfo;
            if (item == null) return;

            var result = MessageBox.Show($"Delete startup item: {item.Name}?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    startupManager.DeleteStartupItem(item);
                    RefreshStartupItems();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ShowStartupFileLocation(object parameter)
        {
            var item = parameter as StartupInfo;
            if (item == null || string.IsNullOrEmpty(item.Path)) return;

            try
            {
                var filePath = item.Path;
                
                // Handle command line arguments in path
                if (filePath.StartsWith("\""))
                {
                    int endQuote = filePath.IndexOf("\"", 1);
                    if (endQuote > 0)
                        filePath = filePath.Substring(1, endQuote - 1);
                }
                else
                {
                    var parts = filePath.Split(' ');
                    filePath = parts[0];
                }

                if (File.Exists(filePath))
                {
                    Process.Start("explorer.exe", $"/select,\"{filePath}\"");
                }
                else
                {
                    MessageBox.Show("File not found", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void TerminateConnection(object parameter)
        {
            var connection = parameter as NetworkConnection;
            if (connection == null) return;

            var result = MessageBox.Show($"Terminate connection from {connection.ProcessName} (PID: {connection.ProcessId})?\n\nThis will kill the process owning the connection.", 
                "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    networkAnalyzer.TerminateConnection(connection);
                    RefreshNetworkConnections();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportToCSV(object parameter)
        {
            try
            {
                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "CSV Files (*.csv)|*.csv",
                    FileName = $"ProcessList_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
                };

                if (dialog.ShowDialog() == true)
                {
                    using (var writer = new StreamWriter(dialog.FileName))
                    {
                        writer.WriteLine("Process Name,PID,CPU %,Memory (MB),User,File Path,Company,Risk Level,Unsigned,Hidden,Startup");
                        foreach (var proc in Processes)
                        {
                            writer.WriteLine($"\"{proc.ProcessName}\",{proc.ProcessId},{proc.CpuUsage:F1},{proc.MemoryUsage / 1024.0 / 1024.0:F1}," +
                                           $"\"{proc.UserAccount}\",\"{proc.FilePath}\",\"{proc.CompanyName}\",{proc.RiskLevel}," +
                                           $"{proc.IsUnsigned},{proc.IsHidden},{proc.IsStartup}");
                        }
                    }
                    MessageBox.Show("Export successful!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class RelayCommand : ICommand
    {
        private readonly Action<object> execute;
        private readonly Predicate<object> canExecute;

        public RelayCommand(Action<object> execute, Predicate<object> canExecute = null)
        {
            this.execute = execute;
            this.canExecute = canExecute;
        }

        public bool CanExecute(object parameter) => canExecute == null || canExecute(parameter);
        public void Execute(object parameter) => execute(parameter);
        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }
    }
}
