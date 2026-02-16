#include "networkserver.h"
#include "logger.h"
#include "util.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <csignal>

namespace fs = std::filesystem;

// Global state for network sharing
static std::atomic<bool> g_network_share_running(false);
static std::atomic<NetworkProtocol> g_current_protocol(NetworkProtocol::NONE);
static NetworkShareOptions g_current_options;
static std::mutex g_network_mutex;

static bool execute_command(const std::string& cmd) {
  log_debug("Executing: " + cmd);
  int result = system((cmd + " > /dev/null 2>&1").c_str());
  return result == 0;
}

static std::string execute_command_output(const std::string& cmd) {
  std::array<char, 128> buffer;
  std::string result;
  FILE* pipe = popen((cmd + " 2>/dev/null").c_str(), "r");
  if (!pipe) return "";
  while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
    result += buffer.data();
  }
  pclose(pipe);
  // Remove trailing newline
  if (!result.empty() && result.back() == '\n') {
    result.pop_back();
  }
  return result;
}

bool has_smb_server() {
  // Check for smbd (Samba server)
  return fs::exists("/usr/sbin/smbd") || 
         fs::exists("/sbin/smbd") || 
         fs::exists("/system/bin/smbd") ||
         !execute_command_output("which smbd").empty() ||
         !execute_command_output("which nmbd").empty();
}

bool has_nfs_server() {
  // Check for NFS server components
  return fs::exists("/usr/sbin/rpc.nfsd") || 
         fs::exists("/sbin/rpc.nfsd") ||
         fs::exists("/usr/sbin/exportfs") ||
         !execute_command_output("which rpc.nfsd").empty();
}

bool has_nbd_server() {
  // Check for NBD server
  return fs::exists("/usr/sbin/nbd-server") || 
         fs::exists("/sbin/nbd-server") ||
         !execute_command_output("which nbd-server").empty();
}

std::string get_local_ip_address() {
  // Try to get IP from common interfaces
  std::vector<std::string> interfaces = {"wlan0", "eth0", "usb0", "rndis0", "ap0"};
  
  for (const auto& iface : interfaces) {
    std::string cmd = "ip -4 addr show " + iface + " 2>/dev/null | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}'";
    std::string ip = execute_command_output(cmd);
    if (!ip.empty()) {
      log_debug("Found IP " + ip + " on interface " + iface);
      return ip;
    }
  }
  
  // Fallback: get first non-loopback IP
  std::string cmd = "ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | grep -v '127.0.0.1' | head -1";
  std::string ip = execute_command_output(cmd);
  if (!ip.empty()) {
    log_debug("Found IP (fallback): " + ip);
    return ip;
  }
  
  // Another fallback using hostname
  cmd = "hostname -I 2>/dev/null | awk '{print $1}'";
  ip = execute_command_output(cmd);
  if (!ip.empty()) {
    return ip;
  }
  
  log_warn("Could not determine local IP address");
  return "";
}

std::string network_protocol_to_string(NetworkProtocol protocol) {
  switch (protocol) {
    case NetworkProtocol::SMB: return "SMB";
    case NetworkProtocol::NFS: return "NFS";
    case NetworkProtocol::NBD: return "NBD";
    default: return "None";
  }
}

// SMB Server Implementation
static bool start_smb_server(const NetworkShareOptions& options) {
  log_info("Starting SMB server...");
  
  std::string share_name = options.share_name.empty() ? "isodrive" : options.share_name;
  
  // Create SMB config directory
  std::string smb_conf_dir = "/data/local/tmp/isodrive_smb";
  fs::create_directories(smb_conf_dir);
  
  // Create SMB configuration file
  std::string smb_conf = smb_conf_dir + "/smb.conf";
  std::ofstream config(smb_conf);
  if (!config) {
    log_error("Failed to create SMB config file");
    return false;
  }
  
  config << "[global]\n";
  config << "  workgroup = WORKGROUP\n";
  config << "  server string = ISOdrive Network Share\n";
  config << "  security = user\n";
  config << "  map to guest = Bad User\n";
  config << "  min protocol = SMB2\n";
  config << "  max protocol = SMB3\n";
  config << "  force user = root\n";
  config << "  force group = root\n";
  config << "  log level = 0\n\n";
  
  config << "[" << share_name << "]\n";
  config << "  path = " << smb_conf_dir << "/content\n";
  config << "  comment = ISOdrive Network Share\n";
  config << "  guest ok = yes\n";
  config << "  read only = " << (options.read_only ? "yes" : "no") << "\n";
  config << "  browseable = yes\n";
  config << "  writable = " << (options.read_only ? "no" : "yes") << "\n";
  config << "  create mask = 0777\n";
  config << "  directory mask = 0777\n";
  config.close();
  
  // Create content directory and symlinks to shared files
  std::string content_dir = smb_conf_dir + "/content";
  fs::create_directories(content_dir);
  
  for (const auto& path : options.paths) {
    std::string filename = fs::path(path).filename();
    std::string link_path = content_dir + "/" + filename;
    
    // Remove existing symlink or file
    if (fs::exists(link_path)) {
      fs::remove(link_path);
    }
    
    // Create symlink to the ISO/IMG file
    try {
      fs::create_symlink(path, link_path);
      log_info("Shared via SMB: " + filename);
    } catch (const fs::filesystem_error& e) {
      log_warn("Failed to create symlink for " + path + ": " + e.what());
    }
  }
  
  // Start smbd if not running
  if (!execute_command("pgrep -x smbd > /dev/null")) {
    std::string cmd = "smbd --configfile=" + smb_conf + " --daemon";
    if (!execute_command(cmd)) {
      log_error("Failed to start smbd");
      return false;
    }
    // Start nmbd as well for network browsing
    execute_command("nmbd --configfile=" + smb_conf + " --daemon");
  }
  
  log_info("SMB server started successfully!");
  return true;
}

static bool stop_smb_server() {
  log_info("Stopping SMB server...");
  
  // Kill smbd and nmbd
  execute_command("killall smbd 2>/dev/null");
  execute_command("killall nmbd 2>/dev/null");
  
  // Clean up config directory
  std::string smb_conf_dir = "/data/local/tmp/isodrive_smb";
  if (fs::exists(smb_conf_dir)) {
    fs::remove_all(smb_conf_dir);
  }
  
  return true;
}

// NFS Server Implementation
static bool start_nfs_server(const NetworkShareOptions& options) {
  log_info("Starting NFS server...");
  
  std::string nfs_export_dir = "/data/local/tmp/isodrive_nfs";
  fs::create_directories(nfs_export_dir);
  
  // Create symlinks to shared files
  for (const auto& path : options.paths) {
    std::string filename = fs::path(path).filename();
    std::string link_path = nfs_export_dir + "/" + filename;
    
    if (fs::exists(link_path)) {
      fs::remove(link_path);
    }
    
    try {
      fs::create_symlink(path, link_path);
      log_info("Shared via NFS: " + filename);
    } catch (const fs::filesystem_error& e) {
      log_warn("Failed to create symlink for " + path + ": " + e.what());
    }
  }
  
  // Export the directory
  std::string exports_file = "/data/local/tmp/isodrive_exports";
  std::ofstream exp_file(exports_file);
  if (exp_file) {
    exp_file << nfs_export_dir << " *(rw,sync,no_subtree_check,no_root_squash)\n";
    exp_file.close();
  }
  
  // Start rpcbind if not running
  execute_command("rpcbind 2>/dev/null");
  
  // Start NFS server
  std::string cmd = "rpc.nfsd 8 2>/dev/null";
  if (!execute_command(cmd)) {
    log_warn("Failed to start rpc.nfsd, trying alternative...");
    // Try without specifying number of threads
    cmd = "rpc.nfsd 2>/dev/null";
    if (!execute_command(cmd)) {
      log_error("Failed to start NFS server");
      return false;
    }
  }
  
  cmd = "rpc.mountd 2>/dev/null";
  execute_command(cmd);
  
  // Exportfs -r to apply exports
  execute_command("exportfs -r 2>/dev/null");
  
  log_info("NFS server started successfully!");
  return true;
}

static bool stop_nfs_server() {
  log_info("Stopping NFS server...");
  
  // Unexport and kill mountd
  execute_command("exportfs -u 2>/dev/null");
  execute_command("killall rpc.mountd 2>/dev/null");
  execute_command("killall rpc.nfsd 2>/dev/null");
  execute_command("killall rpcbind 2>/dev/null");
  
  // Clean up
  std::string nfs_export_dir = "/data/local/tmp/isodrive_nfs";
  if (fs::exists(nfs_export_dir)) {
    fs::remove_all(nfs_export_dir);
  }
  
  return true;
}

// NBD Server Implementation (bootable block device over network)
static bool start_nbd_server(const NetworkShareOptions& options) {
  log_info("Starting NBD (Network Block Device) server...");
  
  if (options.paths.empty()) {
    log_error("NBD requires at least one file to share");
    return false;
  }
  
  // For NBD, we'll share the first file as a block device
  std::string nbd_config = "/data/local/tmp/isodrive_nbd";
  fs::create_directories(nbd_config);
  
  // Create NBD config file
  std::string nbd_conf_file = nbd_config + "/nbd.conf";
  std::ofstream nbd_conf(nbd_conf_file);
  if (!nbd_conf) {
    log_error("Failed to create NBD config file");
    return false;
  }
  
  // NBD configuration for the first file
  std::string nbd_file = options.paths[0];
  std::string filename = fs::path(nbd_file).filename();
  
  nbd_conf << "[generic]\n";
  nbd_conf << "  oldstyle = true\n\n";
  nbd_conf << "[" << filename << "]\n";
  nbd_conf << "  exportfile = " << nbd_file << "\n";
  nbd_conf << "  read_only = " << (options.read_only ? "true" : "false") << "\n";
  nbd_conf << "  multifile = false\n";
  nbd_conf.close();
  
  // Kill existing nbd-server
  execute_command("killall nbd-server 2>/dev/null");
  
  // Determine port (default for NBD is 10809)
  int port = options.port > 0 ? options.port : 10809;
  
  // Start nbd-server
  std::string cmd = "nbd-server -C " + nbd_conf_file + " -p " + std::to_string(port) + " " + nbd_file;
  if (!execute_command(cmd)) {
    log_error("Failed to start nbd-server");
    log_info("Trying alternative method...");
    
    // Try alternative: nbd-server <port> <file>
    cmd = "nbd-server " + std::to_string(port) + " " + nbd_file;
    if (!execute_command(cmd)) {
      log_error("Failed to start NBD server with alternative method");
      return false;
    }
  }
  
  log_info("NBD server started successfully!");
  log_info("Connect with: nbd-client <IP> " + std::to_string(port) + " /dev/nbd0");
  return true;
}

static bool stop_nbd_server() {
  log_info("Stopping NBD server...");
  
  // Kill nbd-server
  execute_command("killall nbd-server 2>/dev/null");
  
  // Clean up
  std::string nbd_config = "/data/local/tmp/isodrive_nbd";
  if (fs::exists(nbd_config)) {
    fs::remove_all(nbd_config);
  }
  
  return true;
}

bool start_network_share(const NetworkShareOptions& options) {
  std::lock_guard<std::mutex> lock(g_network_mutex);
  
  if (g_network_share_running.load()) {
    log_error("Network share already running. Stop it first.");
    return false;
  }
  
  if (options.paths.empty()) {
    log_error("No files specified to share");
    return false;
  }
  
  // Verify all paths exist
  for (const auto& path : options.paths) {
    if (!fs::exists(path)) {
      log_error("File not found: " + path);
      return false;
    }
  }
  
  bool success = false;
  
  switch (options.protocol) {
    case NetworkProtocol::SMB:
      if (!has_smb_server()) {
        log_error("SMB server (smbd) not available on this system");
        return false;
      }
      success = start_smb_server(options);
      break;
      
    case NetworkProtocol::NFS:
      if (!has_nfs_server()) {
        log_error("NFS server not available on this system");
        return false;
      }
      success = start_nfs_server(options);
      break;
      
    case NetworkProtocol::NBD:
      if (!has_nbd_server()) {
        log_error("NBD server (nbd-server) not available on this system");
        return false;
      }
      success = start_nbd_server(options);
      break;
      
    default:
      log_error("Invalid or no network protocol specified");
      return false;
  }
  
  if (success) {
    g_network_share_running.store(true);
    g_current_protocol.store(options.protocol);
    g_current_options = options;
  }
  
  return success;
}

bool stop_network_share() {
  std::lock_guard<std::mutex> lock(g_network_mutex);
  
  if (!g_network_share_running.load()) {
    log_info("No network share is currently running");
    return true;
  }
  
  bool success = false;
  NetworkProtocol protocol = g_current_protocol.load();
  
  switch (protocol) {
    case NetworkProtocol::SMB:
      success = stop_smb_server();
      break;
    case NetworkProtocol::NFS:
      success = stop_nfs_server();
      break;
    case NetworkProtocol::NBD:
      success = stop_nbd_server();
      break;
    default:
      success = false;
  }
  
  g_network_share_running.store(false);
  g_current_protocol.store(NetworkProtocol::NONE);
  
  return success;
}

bool is_network_share_active() {
  return g_network_share_running.load();
}

std::string get_network_share_status() {
  if (!g_network_share_running.load()) {
    return "";
  }
  
  std::ostringstream status;
  NetworkProtocol protocol = g_current_protocol.load();
  
  status << "Protocol: " << network_protocol_to_string(protocol) << "\n";
  
  std::string ip = get_local_ip_address();
  if (!ip.empty()) {
    status << "IP Address: " << ip << "\n";
    
    switch (protocol) {
      case NetworkProtocol::SMB:
        status << "SMB URL: smb://" << ip << "/";
        if (!g_current_options.share_name.empty()) {
          status << g_current_options.share_name;
        } else {
          status << "isodrive";
        }
        status << "\n";
        status << "Windows: \\\\"
               << ip << "\\";
        if (!g_current_options.share_name.empty()) {
          status << g_current_options.share_name;
        } else {
          status << "isodrive";
        }
        status << "\n";
        break;
        
      case NetworkProtocol::NFS:
        status << "NFS URL: " << ip << ":/data/local/tmp/isodrive_nfs\n";
        status << "Mount: mount -t nfs " << ip << ":/data/local/tmp/isodrive_nfs /mnt\n";
        break;
        
      case NetworkProtocol::NBD:
        status << "NBD Port: " << (g_current_options.port > 0 ? g_current_options.port : 10809) << "\n";
        status << "Connect: nbd-client " << ip << " " 
               << (g_current_options.port > 0 ? std::to_string(g_current_options.port) : "10809")
               << " /dev/nbd0\n";
        break;
        
      default:
        break;
    }
  }
  
  status << "Shared files:\n";
  for (const auto& path : g_current_options.paths) {
    status << "  - " << fs::path(path).filename().string() << "\n";
  }
  
  return status.str();
}

