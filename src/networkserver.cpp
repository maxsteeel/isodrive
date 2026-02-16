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
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

namespace fs = std::filesystem;

// Global state for network sharing
static std::atomic<bool> g_network_share_running(false);
static std::atomic<NetworkProtocol> g_current_protocol(NetworkProtocol::NONE);
static NetworkShareOptions g_current_options;
static std::mutex g_network_mutex;
static std::thread g_http_server_thread;
static int g_http_server_socket = -1;

// Default credentials
static const std::string DEFAULT_SMB_USER = "isodrive";
static const std::string DEFAULT_SMB_PASS = "isodrive123";

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

bool has_http_server() {
  // Built-in HTTP server always available
  return true;
}

bool has_iscsi_target() {
  // Check for iSCSI target (tgtd or targetcli)
  return fs::exists("/usr/sbin/tgtd") || 
         fs::exists("/sbin/tgtd") ||
         fs::exists("/usr/bin/targetcli") ||
         fs::exists("/usr/sbin/targetctl") ||
         !execute_command_output("which tgtd").empty() ||
         !execute_command_output("which targetcli").empty();
}

bool has_dnsmasq() {
  return fs::exists("/usr/sbin/dnsmasq") || 
         fs::exists("/sbin/dnsmasq") ||
         !execute_command_output("which dnsmasq").empty();
}

std::string get_local_ip_address() {
  // Try to get IP from common interfaces
  std::vector<std::string> interfaces = {"wlan0", "eth0", "usb0", "rndis0", "ap0", "en0", "wlan1"};
  
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
    case NetworkProtocol::HTTP: return "HTTP (iPXE)";
    case NetworkProtocol::ISCSI: return "iSCSI";
    case NetworkProtocol::NETBOOT: return "NetBoot (DHCP+TFTP+HTTP)";
    default: return "None";
  }
}

// SMB Server Implementation with user/pass
static bool start_smb_server(const NetworkShareOptions& options) {
  log_info("Starting SMB server...");
  
  std::string share_name = options.share_name.empty() ? "isodrive" : options.share_name;
  std::string username = options.username.empty() ? DEFAULT_SMB_USER : options.username;
  std::string password = options.password.empty() ? DEFAULT_SMB_PASS : options.password;
  
  // Create SMB config directory
  std::string smb_conf_dir = "/data/local/tmp/isodrive_smb";
  fs::create_directories(smb_conf_dir);
  
  // Create user if needed (using system user)
  execute_command("id " + username + " 2>/dev/null || useradd -M -s /bin/false " + username);
  execute_command("(echo " + username + ":" + password + " | chpasswd) 2>/dev/null");
  
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
  config << "  security = USER\n";
  config << "  map to guest = Bad User\n";
  config << "  min protocol = SMB2\n";
  config << "  max protocol = SMB3\n";
  config << "  force user = root\n";
  config << "  force group = root\n";
  config << "  log level = 0\n";
  config << "  load printers = no\n";
  config << "  printing = bsd\n";
  config << "  disable spoolss = yes\n\n";
  
  config << "[" << share_name << "]\n";
  config << "  path = " << smb_conf_dir << "/content\n";
  config << "  comment = ISOdrive Network Share\n";
  config << "  valid users = " << username << "\n";
  config << "  guest ok = no\n";
  config << "  read only = " << (options.read_only ? "yes" : "no") << "\n";
  config << "  browseable = yes\n";
  config << "  writable = " << (options.read_only ? "no" : "yes") << "\n";
  config << "  create mask = 0777\n";
  config << "  directory mask = 0777\n";
  config << "  follow symlinks = yes\n";
  config << "  wide links = yes\n";
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
  
  // Stop any existing smbd
  execute_command("killall smbd 2>/dev/null");
  execute_command("killall nmbd 2>/dev/null");
  sleep(1);
  
  // Start smbd
  std::string cmd = "smbd --configfile=" + smb_conf + " --daemon";
  if (!execute_command(cmd)) {
    log_error("Failed to start smbd");
    return false;
  }
  
  // Start nmbd for network browsing
  execute_command("nmbd --configfile=" + smb_conf + " --daemon");
  
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

// HTTP Server Implementation with iPXE support - FIXED VERSION
static bool handle_http_request(int client_fd, const std::string& path, int http_port) {
  try {
    // Extract filename from path
    std::string filename;
    if (path == "/" || path == "/boot.ipxe") {
      // Handle iPXE script request
      std::ostringstream ipxe_script;
      ipxe_script << "#!ipxe\n";
      ipxe_script << "echo ========================================\n";
      ipxe_script << "echo    ISOdrive Network Boot\n";
      ipxe_script << "echo ========================================\n";
      ipxe_script << "echo\n";
      
      std::string ip = get_local_ip_address();
      
      // Menu for boot options
      ipxe_script << "menu ISOdrive Boot Menu\n";
      ipxe_script << "item local Boot from local disk\n";
      
      int idx = 1;
      for (const auto& file : g_current_options.paths) {
        std::string fname = fs::path(file).filename();
        ipxe_script << "item boot_" << idx << " " << fname << "\n";
        idx++;
      }
      ipxe_script << "choose --timeout 5000 --default local selected || goto local\n";
      ipxe_script << "goto ${selected}\n";
      
      idx = 1;
      for (const auto& file : g_current_options.paths) {
        std::string fname = fs::path(file).filename();
        ipxe_script << ":boot_" << idx << "\n";
        ipxe_script << "echo Booting " << fname << "...\n";
        ipxe_script << "kernel http://" << ip << ":" << http_port << "/" << fname << "\n";
        ipxe_script << "boot\n";
        idx++;
      }
      
      ipxe_script << ":local\n";
      ipxe_script << "exit\n";
      
      std::string script = ipxe_script.str();
      std::string response = "HTTP/1.1 200 OK\r\n";
      response += "Content-Type: text/plain\r\n";
      response += "Content-Length: " + std::to_string(script.length()) + "\r\n";
      response += "X-Theme: ipxe\r\n";
      response += "\r\n";
      response += script;
      
      send(client_fd, response.c_str(), response.length(), 0);
      return true;
    }
    
    // Extract filename from path (remove leading /)
    filename = path;
    if (filename.length() > 0 && filename[0] == '/') {
      filename = filename.substr(1);
    }
    
    std::string file_path = "/data/local/tmp/isodrive_http/content/" + filename;
    
    if (!fs::exists(file_path)) {
      std::string not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
      send(client_fd, not_found.c_str(), not_found.length(), 0);
      return false;
    }
    
    // Get file size
    uint64_t file_size = fs::file_size(file_path);
    
    // Send HTTP headers
    std::ostringstream response;
    response << "HTTP/1.1 200 OK\r\n";
    response << "Content-Type: application/octet-stream\r\n";
    response << "Content-Length: " << file_size << "\r\n";
    response << "Content-Disposition: attachment; filename=\"" << filename << "\"\r\n";
    response << "Accept-Ranges: bytes\r\n";
    response << "Access-Control-Allow-Origin: *\r\n";
    response << "\r\n";
    
    std::string headers = response.str();
    send(client_fd, headers.c_str(), headers.length(), 0);
    
    // Send file content in chunks
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
      return false;
    }
    
    char buffer[8192];
    while (file.good() && g_network_share_running.load()) {
      file.read(buffer, sizeof(buffer));
      ssize_t bytes_read = file.gcount();
      if (bytes_read > 0) {
        ssize_t sent = send(client_fd, buffer, bytes_read, 0);
        if (sent <= 0) break;
      }
    }
    
    return true;
  } catch (const std::exception& e) {
    log_error("HTTP request error: " + std::string(e.what()));
    return false;
  }
}

static void http_server_worker(int port) {
  // Set up signal handling for this thread
  signal(SIGPIPE, SIG_IGN);
  
  g_http_server_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (g_http_server_socket < 0) {
    log_error("Failed to create HTTP server socket");
    return;
  }
  
  int opt = 1;
  setsockopt(g_http_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(port);
  
  if (bind(g_http_server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
    log_error("Failed to bind HTTP server to port " + std::to_string(port));
    close(g_http_server_socket);
    g_http_server_socket = -1;
    return;
  }
  
  if (listen(g_http_server_socket, 5) < 0) {
    log_error("Failed to listen on HTTP server");
    close(g_http_server_socket);
    g_http_server_socket = -1;
    return;
  }
  
  log_info("HTTP server listening on port " + std::to_string(port));
  
  while (g_network_share_running.load()) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Use timeout to allow checking g_network_share_running
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(g_http_server_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int client_fd = accept(g_http_server_socket, (struct sockaddr*)&client_addr, &client_len);
    
    // Reset timeout
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(g_http_server_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    if (client_fd < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Timeout - continue loop to check running flag
        continue;
      }
      if (g_network_share_running.load()) {
        log_warn("Failed to accept HTTP connection");
      }
      continue;
    }
    
    // Simple HTTP request parsing
    char buffer[2048];
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_read > 0) {
      buffer[bytes_read] = '\0';
      
      // Parse request line
      std::string request(buffer);
      std::istringstream iss(request);
      std::string method, req_path, http_version;
      iss >> method >> req_path >> http_version;
      
      log_debug("HTTP request: " + method + " " + req_path);
      
      // Handle request
      handle_http_request(client_fd, req_path, port);
    }
    
    close(client_fd);
  }
  
  if (g_http_server_socket >= 0) {
    close(g_http_server_socket);
    g_http_server_socket = -1;
  }
  
  log_info("HTTP server thread exiting");
}

static bool start_http_server(const NetworkShareOptions& options) {
  log_info("Starting HTTP server (iPXE boot support)...");
  
  int port = options.port > 0 ? options.port : 8080;
  
  // Create HTTP content directory
  std::string http_content_dir = "/data/local/tmp/isodrive_http/content";
  fs::create_directories(http_content_dir);
  
  // Create symlinks to shared files
  for (const auto& path : options.paths) {
    std::string filename = fs::path(path).filename();
    std::string link_path = http_content_dir + "/" + filename;
    
    if (fs::exists(link_path)) {
      fs::remove(link_path);
    }
    
    try {
      fs::create_symlink(path, link_path);
      log_info("Shared via HTTP: " + filename);
    } catch (const fs::filesystem_error& e) {
      log_warn("Failed to create symlink for " + path + ": " + e.what());
    }
  }
  
  // Start HTTP server in background thread - DETACH to prevent crash on main exit
  g_http_server_thread = std::thread(http_server_worker, port);
  
  // Wait a bit for server to start
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  
  if (g_http_server_socket < 0) {
    log_error("Failed to start HTTP server");
    if (g_http_server_thread.joinable()) {
      g_http_server_thread.detach();
    }
    return false;
  }
  
  log_info("HTTP server started successfully!");
  return true;
}

static bool stop_http_server() {
  log_info("Stopping HTTP server...");
  
  g_network_share_running.store(false);
  
  // Close socket to unblock accept
  if (g_http_server_socket >= 0) {
    close(g_http_server_socket);
    g_http_server_socket = -1;
  }
  
  // Give thread time to exit
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  
  // Detach to avoid hanging
  if (g_http_server_thread.joinable()) {
    g_http_server_thread.detach();
  }
  
  // Clean up
  std::string http_content_dir = "/data/local/tmp/isodrive_http";
  if (fs::exists(http_content_dir)) {
    fs::remove_all(http_content_dir);
  }
  
  return true;
}

// NetBoot Server (DHCP + TFTP + HTTP) using dnsmasq
static bool start_netboot_server(const NetworkShareOptions& options) {
  log_info("Starting NetBoot server (DHCP + TFTP + HTTP)...");
  
  if (!has_dnsmasq()) {
    log_error("dnsmasq not available on this system");
    return false;
  }
  
  std::string ip = get_local_ip_address();
  if (ip.empty()) {
    log_error("Cannot determine IP address for NetBoot");
    return false;
  }
  
  // Start HTTP server first (required for iPXE booting)
  if (!start_http_server(options)) {
    log_error("Failed to start HTTP server for NetBoot");
    return false;
  }
  
  // Create dnsmasq config
  std::string dnsmasq_conf_dir = "/data/local/tmp/isodrive_netboot";
  fs::create_directories(dnsmasq_conf_dir);
  fs::create_directories(dnsmasq_conf_dir + "/tftp");
  
  std::string dnsmasq_conf = dnsmasq_conf_dir + "/dnsmasq.conf";
  std::ofstream config(dnsmasq_conf);
  if (!config) {
    log_error("Failed to create dnsmasq config");
    stop_http_server();
    return false;
  }
  
  // Extract base IP (e.g., 192.168.9 from 192.168.9.116)
  std::string base_ip = ip.substr(0, ip.rfind('.'));
  
  config << "interface=wlan0\n";
  config << "bind-interfaces\n";
  config << "dhcp-range=" << base_ip << ".100," << base_ip << ".250,255.255.255.0,12h\n";
  config << "dhcp-option=3," << ip << "\n";  // Router
  config << "dhcp-option=6," << ip << "\n";   // DNS
  config << "dhcp-host=00:00:00:00:00:00,set:ipxe\n";  // For PXE clients
  config << "dhcp-match=set:ipxe,option:client-arch,0\n";
  config << "dhcp-boot=tag:ipxe,http://" << ip << ":8080/boot.ipxe\n";
  config << "enable-tftp\n";
  config << "tftp-root=" << dnsmasq_conf_dir << "/tftp\n";
  config << "log-dhcp\n";
  config << "log-queries\n";
  config << "quiet-dhcp\n";
  config << "quiet-dhcp6\n";
  config << "quiet-ra\n";
  config.close();
  
  // Create a simple iPXE boot script in TFTP root
  std::ofstream tftp_script(dnsmasq_conf_dir + "/tftp/boot.ipxe");
  if (tftp_script) {
    tftp_script << "#!ipxe\n";
    tftp_script << "echo ========================================\n";
    tftp_script << "echo    ISOdrive NetBoot\n";
    tftp_script << "echo ========================================\n";
    tftp_script << "echo\n";
    tftp_script << "echo Fetching boot menu from HTTP...\n";
    tftp_script << "chain http://" << ip << ":8080/boot.ipxe\n";
    tftp_script.close();
  }
  
  // Stop any existing dnsmasq
  execute_command("killall dnsmasq 2>/dev/null");
  sleep(1);
  
  // Start dnsmasq
  std::string cmd = "dnsmasq -C " + dnsmasq_conf + " --no-daemon --log-queries";
  if (!execute_command(cmd)) {
    log_error("Failed to start dnsmasq");
    // Try without --log-queries
    cmd = "dnsmasq -C " + dnsmasq_conf;
    if (!execute_command(cmd)) {
      log_error("Failed to start dnsmasq (second attempt)");
      stop_http_server();
      return false;
    }
  }
  
  log_info("NetBoot server started successfully!");
  log_info("Clients can now boot directly from network!");
  log_info("Connect to WiFi AP and boot from network (PXE)");
  
  return true;
}

static bool stop_netboot_server() {
  log_info("Stopping NetBoot server...");
  
  // Stop dnsmasq
  execute_command("killall dnsmasq 2>/dev/null");
  
  // Stop HTTP server
  stop_http_server();
  
  // Clean up
  std::string netboot_conf_dir = "/data/local/tmp/isodrive_netboot";
  if (fs::exists(netboot_conf_dir)) {
    fs::remove_all(netboot_conf_dir);
  }
  
  return true;
}

// iSCSI Target Implementation
static bool start_iscsi_server(const NetworkShareOptions& options) {
  log_info("Starting iSCSI target server...");
  
  if (options.paths.empty()) {
    log_error("iSCSI requires at least one file to share");
    return false;
  }
  
  // For iSCSI, we'll use the first file as the LUN
  std::string iscsi_file = options.paths[0];
  std::string filename = fs::path(iscsi_file).filename();
  
  // Check for targetcli (modern way)
  bool has_targetcli = fs::exists("/usr/bin/targetcli") || fs::exists("/usr/sbin/targetcli");
  
  if (has_targetcli) {
    // Use targetcli to create iSCSI target
    std::string target_iqn = "iqn.2024-02.isodrive:share1";
    
    // Create backstore
    execute_command("targetcli /backstores/fileio create name=" + filename + " file=" + iscsi_file);
    
    // Create target
    execute_command("targetcli /iscsi create " + target_iqn);
    
    // Create LUN
    execute_command("targetcli /iscsi/" + target_iqn + "/tpg1/luns create /backstores/fileio/" + filename);
    
    // Set authentication (if needed)
    execute_command("targetcli /iscsi/" + target_iqn + "/tpg1 set attribute authentication=0");
    
    // Enable target
    execute_command("targetcli /iscsi/" + target_iqn + "/tpg1 set attribute generate_node_acls=1");
    
    log_info("iSCSI target created: " + target_iqn);
    log_info("Connect from other device using:");
    log_info("  iscsiadm --mode discovery --type sendtargets --portal " + get_local_ip_address());
  } else {
    // Try legacy tgtd approach
    std::string iscsi_conf_dir = "/data/local/tmp/isodrive_iscsi";
    fs::create_directories(iscsi_conf_dir);
    
    // Create ietd.conf style config
    std::string iscsi_conf = iscsi_conf_dir + "/ietd.conf";
    std::ofstream config(iscsi_conf);
    if (config) {
      config << "Target iqn.2024-02.isodrive:share1\n";
      config << "  Lun 0 Path=" << iscsi_file << ",Type=fileio\n";
      config << "  MaxConnections 5\n";
      config.close();
    }
    
    // Start tgtd
    execute_command("tgtd --config=" + iscsi_conf + " -f");
    sleep(1);
    
    // Setup target
    execute_command("ietadm --op new --tid=1 --targetname=iqn.2024-02.isodrive:share1");
    execute_command("ietadm --op new --tid=1 --lun=0 --params Path=" + iscsi_file);
    
    log_info("iSCSI target started (legacy mode)");
  }
  
  log_info("iSCSI server started successfully!");
  return true;
}

static bool stop_iscsi_server() {
  log_info("Stopping iSCSI server...");
  
  // Try targetctl first
  if (execute_command("targetctl clear")) {
    // targetctl worked
  }
  
  // Kill processes
  execute_command("killall tgtd 2>/dev/null");
  execute_command("killall targetd 2>/dev/null");
  
  // Clean up
  std::string iscsi_conf_dir = "/data/local/tmp/isodrive_iscsi";
  if (fs::exists(iscsi_conf_dir)) {
    fs::remove_all(iscsi_conf_dir);
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
  
  g_network_share_running.store(true);
  
  bool success = false;
  
  switch (options.protocol) {
    case NetworkProtocol::SMB:
      if (!has_smb_server()) {
        log_error("SMB server (smbd) not available on this system");
        g_network_share_running.store(false);
        return false;
      }
      success = start_smb_server(options);
      break;
      
    case NetworkProtocol::HTTP:
      if (!has_http_server()) {
        log_error("HTTP server not available");
        g_network_share_running.store(false);
        return false;
      }
      success = start_http_server(options);
      break;
      
    case NetworkProtocol::ISCSI:
      if (!has_iscsi_target()) {
        log_error("iSCSI target (targetcli/tgtd) not available on this system");
        g_network_share_running.store(false);
        return false;
      }
      success = start_iscsi_server(options);
      break;
      
    case NetworkProtocol::NETBOOT:
      success = start_netboot_server(options);
      break;
      
    default:
      log_error("Invalid or no network protocol specified");
      g_network_share_running.store(false);
      return false;
  }
  
  if (success) {
    g_current_protocol.store(options.protocol);
    g_current_options = options;
  } else {
    g_network_share_running.store(false);
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
    case NetworkProtocol::HTTP:
      success = stop_http_server();
      break;
    case NetworkProtocol::ISCSI:
      success = stop_iscsi_server();
      break;
    case NetworkProtocol::NETBOOT:
      success = stop_netboot_server();
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
      case NetworkProtocol::SMB: {
        std::string username = g_current_options.username.empty() ? DEFAULT_SMB_USER : g_current_options.username;
        std::string password = g_current_options.password.empty() ? DEFAULT_SMB_PASS : g_current_options.password;
        std::string share_name = g_current_options.share_name.empty() ? "isodrive" : g_current_options.share_name;
        
        status << "SMB URL: smb://" << ip << "/" << share_name << "\n";
        status << "Windows: \\\\" << ip << "\\" << share_name << "\n";
        status << "Username: " << username << "\n";
        status << "Password: " << password << "\n";
        break;
      }
        
      case NetworkProtocol::HTTP: {
        int port = g_current_options.port > 0 ? g_current_options.port : 8080;
        status << "HTTP Port: " << port << "\n";
        status << "iPXE Script: http://" << ip << ":" << port << "/boot.ipxe\n";
        status << "\n";
        status << "Download URLs:\n";
        for (const auto& path : g_current_options.paths) {
          std::string filename = fs::path(path).filename();
          status << "  http://" << ip << ":" << port << "/" << filename << "\n";
        }
        status << "\n";
        status << "iPXE Boot Commands:\n";
        status << "  chainloader http://" << ip << ":" << port << "/boot.ipxe\n";
        break;
      }
        
      case NetworkProtocol::NETBOOT: {
        status << "DHCP Range: " << ip.substr(0, ip.rfind('.')) << ".100-250\n";
        status << "TFTP Server: " << ip << "\n";
        status << "HTTP Port: 8080\n";
        status << "\n";
        status << "=== NETBOOT INSTRUCTIONS ===\n";
        status << "1. Create a WiFi hotspot on this device\n";
        status << "2. Connect PC to the WiFi hotspot\n";
        status << "3. Boot PC from network (PXE/NET) in BIOS/UEFI\n";
        status << "4. iPXE will automatically fetch boot menu\n";
        status << "\n";
        status << "Manual iPXE boot:\n";
        status << "  iPXE> chainloader http://" << ip << ":8080/boot.ipxe\n";
        break;
      }
        
      case NetworkProtocol::ISCSI: {
        status << "iSCSI Target: iqn.2024-02.isodrive:share1\n";
        status << "Portal: " << ip << ":3260\n";
        status << "\n";
        status << "Connect on Linux:\n";
        status << "  iscsiadm --mode discovery --type sendtargets --portal " << ip << "\n";
        status << "  iscsiadm --mode node --targetname iqn.2024-02.isodrive:share1 --portal " << ip << " --login\n";
        status << "\n";
        status << "Connect on Windows:\n";
        status << "  Use iSCSI Initiator, add target: " << ip << "\n";
        break;
      }
        
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
