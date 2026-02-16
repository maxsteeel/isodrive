#include "androidusbisomanager.h"
#include "configfsisomanager.h"
#include "logger.h"
#include "networkserver.h"
#include "util.h"
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <cstdint>

void print_help() {
  std::cout << "Usage:\n"
            << "isodrive [FILE]... [OPTION]...\n"
            << "Mounts the given FILE(s) as bootable device(s) using configfs.\n"
            << "Supports both ISO and IMG files, with multi-LUN support for mounting\n"
            << "multiple files as separate drives.\n"
            << "Run without any arguments to unmount any mounted files and display "
               "this help message.\n\n"
            << "Optional arguments:\n"
            << "-rw\t\t Mounts the file in read write mode.\n"
            << "-cdrom\t\t Mounts the file as a cdrom.\n"
            << "-hdd\t\t Forces the file to be mounted as a hard disk (disables auto-detect).\n\n"
            << "Windows ISO options:\n"
            << "-windows\t Enables Windows ISO mode (auto-detects if not specified).\n"
            << "-win10\t\t Forces Windows 10 mode.\n"
            << "-win11\t\t Forces Windows 11 mode.\n"
            << "-usb3\t\t Uses USB 3.0 (SuperSpeed) descriptors.\n\n"
            << "Multi-LUN options:\n"
            << "-multi\t\t Enables multi-LUN mode for mounting multiple files.\n\n"
            << "Image creation options:\n"
            << "-create\t\t Creates an IMG file with specified size.\n"
            << "\t\t Usage: -create [path] [size] [options]\n"
            << "\t\t Example: -create example.img 2GB -dynamic -rw\n"
            << "\t\t Size formats: 2GB, 500MB, 1TB, 1024KB, etc.\n"
            << "\t\t Options:\n"
            << "\t\t   -dynamic\t Creates a sparse file (grows on demand).\n"
            << "\t\t   -rw\t\t Sets the file as read-write (default: read-only).\n"
            << "\t\t   -format\t Formats the IMG after creation (auto-detect).\n"
            << "\t\t   -fat32\t Formats as FAT32 (requires mkfs.fat).\n"
            << "\t\t   -exfat\t Formats as exFAT (requires mkfs.exfat).\n"
            << "\t\t   -ntfs\t Formats as NTFS (requires mkfs.ntfs).\n"
            << "\t\t   -ext4\t Formats as ext4 (requires mkfs.ext4).\n"
            << "\t\t   -btrfs\t Formats as btrfs (requires mkfs.btrfs).\n"
            << "\t\t   -label \"NAME\"\t Sets the volume label.\n\n"
            << "Backend options:\n"
            << "-configfs\t Forces the app to use configfs.\n"
            << "-usbgadget\t Forces the app to use sysfs.\n\n"
            << "Output options:\n"
            << "-v, -verbose\t Enables verbose/debug output.\n"
            << "-q, -quiet\t Suppresses all output except errors.\n\n"
            << "Network sharing options:\n"
            << "-net\t\t Enable network sharing (requires protocol: smb, http, iscsi).\n"
            << "\t\t Usage: -net [protocol] [FILE]...\n"
            << "\t\t Example: -net smb test.img -user admin -pass 123456\n"
            << "\t\t Example: -net http boot.img\n"
            << "\t\t Example: -net iscsi boot.img\n\n"
            << "Network protocols:\n"
            << "  smb\t\t SMB/CIFS (Windows file sharing) - NOT bootable\n"
            << "  http\t\t HTTP Server (iPXE boot) - BOOTABLE\n"
            << "  iscsi\t\t iSCSI (Network Block Device) - BOOTABLE\n\n"
            << "Network SMB options:\n"
            << "  -user\t\t Username for SMB (default: isodrive)\n"
            << "  -pass\t\t Password for SMB (default: isodrive123)\n\n"
            << "Network management:\n"
            << "-net-status\t Show current network share status.\n"
            << "-net-stop\t Stop the current network share.\n\n";
}

bool configs(const std::string& iso_target, bool cdrom, bool ro, const WindowsMountOptions& win_opts) {
  log_info("Using configfs!");

  if (!supported())
  {
    log_error("usb_gadget is not supported!");
    return false;
  }
  
  return mount_iso(iso_target, cdrom, ro, win_opts);
}

bool configs_multi(const std::vector<std::string>& iso_paths,
                   const std::vector<bool>& cdroms,
                   const std::vector<bool>& ros,
                   const WindowsMountOptions& win_opts) {
  log_info("Using configfs (multi-LUN mode)!");

  if (!supported())
  {
    log_error("usb_gadget is not supported!");
    return false;
  }

  if (iso_paths.empty()) {
    return unmount_all_isos();
  }
  
  return mount_multiple_isos(iso_paths, cdroms, ros, win_opts);
}

bool usb(const std::string& iso_target, bool cdrom, bool ro) {
  log_info("Using sysfs!");
  if (!usb_supported())
  {
    log_error("usb_gadget is not supported!");
    return false;
  }
  if (cdrom || !ro)
  {
    log_warn("cdrom/ro flags ignored. (this is expected for sysfs backend)");
  }
  if (iso_target.empty())
    return usb_reset_iso();
  else
    return usb_mount_iso(iso_target);
}

bool handle_create_mode(const std::string& img_path, const std::string& size_str, 
                        bool dynamic, bool rw, const std::string& format_type,
                        const std::string& label) {
  uint64_t size = 0;
  
  if (!parse_size_string(size_str, &size)) {
    log_error("Invalid size format: " + size_str);
    log_info("Valid formats: 2GB, 500MB, 1TB, 1024KB, etc.");
    return false;
  }
  
  if (!check_available_space(img_path, size)) {
    return false;
  }
  
  bool success = create_img_file(img_path, size, dynamic, !rw);
  if (!success) {
    return false;
  }
  
  if (!format_type.empty()) {
    success = format_img_file(img_path, format_type, label);
    if (!success) {
      return false;
    }
  }
  
  return true;
}

int main(int argc, char *argv[]) {
  if (getuid() != 0) {
    std::cerr << "Permission denied" << std::endl;
    return 1;
  }

  bool multi_mode = false;
  bool create_mode = false;
  bool net_mode = false;
  bool net_stop = false;
  bool net_status = false;
  NetworkProtocol net_protocol = NetworkProtocol::NONE;
  std::string create_path;
  std::string create_size;
  bool create_dynamic = false;
  bool create_rw = false;
  std::string create_format;
  std::string create_label;
  
  // Network options
  std::string net_user;
  std::string net_pass;
  uint16_t net_port = 0;
  
  std::vector<std::string> iso_targets;
  std::vector<bool> cdroms;
  std::vector<bool> ros;
  std::vector<bool> force_hdds;
  
  bool default_cdrom = false;
  bool default_ro = true;
  bool default_force_hdd = false;
  
  bool force_configfs = false;
  bool force_usbgadget = false;
  
  bool windows_mode = false;
  bool force_win10 = false;
  bool force_win11 = false;
  bool use_usb3 = false;

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-rw") {
      if (create_mode) {
        create_rw = true;
      } else {
        default_ro = false;
        for (size_t j = 0; j < iso_targets.size(); j++) {
          if (j >= ros.size()) ros.push_back(false);
          else ros[j] = false;
        }
      }
    } else if (arg == "-cdrom") {
      default_cdrom = true;
      for (size_t j = 0; j < iso_targets.size(); j++) {
        if (j >= cdroms.size()) cdroms.push_back(true);
        else cdroms[j] = true;
      }
    } else if (arg == "-hdd") {
      default_force_hdd = true;
      for (size_t j = 0; j < iso_targets.size(); j++) {
        if (j >= force_hdds.size()) force_hdds.push_back(true);
        else force_hdds[j] = true;
      }
    } else if (arg == "-windows") {
      windows_mode = true;
    } else if (arg == "-win10") {
      windows_mode = true;
      force_win10 = true;
    } else if (arg == "-win11") {
      windows_mode = true;
      force_win11 = true;
    } else if (arg == "-usb3") {
      use_usb3 = true;
    } else if (arg == "-multi" || arg == "--multi") {
      multi_mode = true;
    } else if (arg == "-create") {
      create_mode = true;
    } else if (arg == "-dynamic") {
      create_dynamic = true;
    } else if (arg == "-format") {
      create_format = "auto";
    } else if (arg == "-fat32") {
      create_format = "fat32";
    } else if (arg == "-exfat") {
      create_format = "exfat";
    } else if (arg == "-ntfs") {
      create_format = "ntfs";
    } else if (arg == "-ext4") {
      create_format = "ext4";
    } else if (arg == "-btrfs") {
      create_format = "btrfs";
    } else if (arg == "-label") {
      if (i + 1 < argc) {
        create_label = argv[++i];
      }
    } else if (arg == "-net") {
      net_mode = true;
      // Next argument should be the protocol
      if (i + 1 < argc) {
        std::string proto = argv[++i];
        if (proto == "smb") {
          net_protocol = NetworkProtocol::SMB;
        } else if (proto == "http") {
          net_protocol = NetworkProtocol::HTTP;
        } else if (proto == "iscsi") {
          net_protocol = NetworkProtocol::ISCSI;
        } else {
          log_error("Invalid network protocol: " + proto);
          log_info("Valid protocols: smb, http, iscsi");
          return 1;
        }
      } else {
        log_error("Missing network protocol after -net");
        log_info("Usage: -net [smb|http|iscsi] [file]...");
        return 1;
      }
    } else if (arg == "-user") {
      if (i + 1 < argc) {
        net_user = argv[++i];
      }
    } else if (arg == "-pass") {
      if (i + 1 < argc) {
        net_pass = argv[++i];
      }
    } else if (arg == "-port") {
      if (i + 1 < argc) {
        net_port = std::stoi(argv[++i]);
      }
    } else if (arg == "-net-stop") {
      net_stop = true;
    } else if (arg == "-net-status") {
      net_status = true;
    } else if (arg == "-configfs") {
      force_configfs = true;
    } else if (arg == "-usbgadget") {
      force_usbgadget = true;
    } else if (arg == "-v" || arg == "-verbose") {
      log_set_level(LogLevel::DEBUG);
    } else if (arg == "-q" || arg == "-quiet") {
      log_set_level(LogLevel::ERROR);
    } else if (arg[0] != '-') {
      if (create_mode) {
        if (create_path.empty()) {
          create_path = arg;
        } else if (create_size.empty()) {
          create_size = arg;
        } else {
          iso_targets.push_back(arg);
        }
      } else {
        iso_targets.push_back(arg);
        if (default_cdrom) {
          if (cdroms.size() < iso_targets.size()) cdroms.push_back(true);
        }
        if (!default_ro) {
          if (ros.size() < iso_targets.size()) ros.push_back(false);
        }
        if (default_force_hdd) {
          if (force_hdds.size() < iso_targets.size()) force_hdds.push_back(true);
        }
      }
    }
  }

  if (argc == 1) {
    print_help();
  }

  // Handle network share stop
  if (net_stop) {
    if (stop_network_share()) {
      log_info("Network share stopped successfully");
      return 0;
    } else {
      log_error("Failed to stop network share");
      return 1;
    }
  }

  // Handle network share status
  if (net_status) {
    if (is_network_share_active()) {
      std::string status = get_network_share_status();
      if (!status.empty()) {
        std::cout << "\n=== Network Share Status ===\n";
        std::cout << status;
        std::cout << "============================\n";
      } else {
        log_info("Network share is active but no status available");
      }
      return 0;
    } else {
      log_info("No network share is currently active");
      return 0;
    }
  }

  // Handle network sharing mode
  if (net_mode) {
    if (net_protocol == NetworkProtocol::NONE) {
      log_error("No network protocol specified");
      log_info("Usage: -net [smb|http|iscsi] [file]...");
      return 1;
    }
    
    if (iso_targets.empty()) {
      log_error("No files specified for network sharing");
      return 1;
    }
    
    // Resolve all paths
    for (size_t j = 0; j < iso_targets.size(); j++) {
      std::string resolved = resolve_path(iso_targets[j]);
      if (resolved.empty()) {
        log_error("File not found: " + iso_targets[j]);
        return 1;
      }
      iso_targets[j] = resolved;
    }
    
    // Create network share options
    NetworkShareOptions net_opts;
    net_opts.protocol = net_protocol;
    net_opts.paths = iso_targets;
    net_opts.read_only = true;
    net_opts.username = net_user;
    net_opts.password = net_pass;
    net_opts.port = net_port;
    
    if (start_network_share(net_opts)) {
      std::cout << "\n=== Network Share Started ===\n";
      std::cout << get_network_share_status();
      std::cout << "=============================\n";
      return 0;
    } else {
      log_error("Failed to start network share");
      return 1;
    }
  }

  if (create_mode) {
    if (create_path.empty() || create_size.empty()) {
      log_error("Missing arguments for -create");
      log_info("Usage: -create [path] [size] [options]");
      log_info("Example: -create example.img 2GB -dynamic -rw");
      return 1;
    }
    
    // Resolve create_path with CWD support
    std::string resolved_create_path = resolve_path(create_path);
    if (!resolved_create_path.empty()) {
      log_info("Resolved: " + create_path + " -> " + resolved_create_path);
      create_path = resolved_create_path;
    } else if (create_path[0] != '/') {
      // Only warn if it's a relative path that wasn't resolved
      log_warn("Could not resolve path, file will be created as: " + create_path);
    }
    
    return handle_create_mode(create_path, create_size, create_dynamic, create_rw, create_format, create_label) ? 0 : 1;
  }

  if (force_win10 && force_win11) {
    log_error("Incompatible arguments -win10 and -win11");
    return 1;
  }

  if (multi_mode) {
    if (iso_targets.empty()) {
      log_info("No files specified, unmounting all ISOs...");
    } else {
      // Resolve all paths with CWD support
      for (size_t j = 0; j < iso_targets.size(); j++) {
        std::string resolved = resolve_path(iso_targets[j]);
        if (resolved.empty()) {
          log_error("File not found: " + iso_targets[j]);
          log_info("Resolved path was: " + iso_targets[j]);
          return 1;
        }
        log_info("Resolved: " + iso_targets[j] + " -> " + resolved);
        iso_targets[j] = resolved;
      }
    }

    WindowsMountOptions win_opts = {};
    win_opts.enabled = false;
    win_opts.version = WindowsVersion::NONE;
    win_opts.use_usb3 = use_usb3;
    win_opts.has_uefi = false;
    win_opts.has_legacy = false;

    if (!iso_targets.empty() && !force_hdds.empty() && force_hdds[0]) {
      log_info("HDD mode forced, skipping Windows detection");
    } else if (!iso_targets.empty()) {
      for (size_t j = 0; j < iso_targets.size(); j++) {
        WindowsIsoInfo iso_info = get_windows_iso_info(iso_targets[j]);
        
        if (iso_info.is_windows || windows_mode) {
          if (!win_opts.enabled) {
            win_opts.enabled = true;
          }
          
          if (force_win11) {
            win_opts.version = WindowsVersion::WIN11;
          } else if (force_win10) {
            win_opts.version = WindowsVersion::WIN10;
          } else if (iso_info.is_windows) {
            win_opts.version = iso_info.version;
          } else {
            win_opts.version = WindowsVersion::WIN_UNKNOWN;
          }
          
          win_opts.has_uefi = win_opts.has_uefi || iso_info.has_uefi;
          win_opts.has_legacy = win_opts.has_legacy || iso_info.has_legacy;
          
          if (iso_info.is_windows && !windows_mode) {
            log_info("Windows ISO detected: " + iso_targets[j]);
            log_info("Auto-enabling Windows mode.");
          }
        } else if (!force_hdds.empty() && !force_hdds[j]) {
          if (!is_hybrid_iso(iso_targets[j])) {
            if (j >= cdroms.size()) {
              cdroms.push_back(true);
            } else {
              cdroms[j] = true;
            }
            log_info("Non-hybrid ISO detected: " + iso_targets[j] + ", using CD-ROM mode");
          }
        } else if (!is_hybrid_iso(iso_targets[j])) {
          if (j >= cdroms.size()) {
            cdroms.push_back(true);
          } else {
            cdroms[j] = true;
          }
          log_info("Non-hybrid ISO detected: " + iso_targets[j] + ", using CD-ROM mode");
        }
      }
    }

    while (cdroms.size() < iso_targets.size()) cdroms.push_back(false);
    while (ros.size() < iso_targets.size()) ros.push_back(true);
    while (force_hdds.size() < iso_targets.size()) force_hdds.push_back(false);

    bool success = false;

    if (force_usbgadget) {
      log_error("Multi-LUN mode requires configfs backend");
      return 1;
    } else if (force_configfs || supported()) {
      success = configs_multi(iso_targets, cdroms, ros, win_opts);
    } else {
      log_error("Device does not support isodrive");
      return 1;
    }

    return success ? 0 : 1;
  }

  std::string iso_target = iso_targets.empty() ? "" : iso_targets[0];
  bool cdrom = default_cdrom;
  bool ro = default_ro;
  bool force_hdd = default_force_hdd;

  if (cdrom && !ro && !windows_mode) {
    log_error("Incompatible arguments -cdrom and -rw");
    return 1;
  }

  if (cdrom && force_hdd) {
    log_error("Incompatible arguments -cdrom and -hdd");
    return 1;
  }

  if (!iso_target.empty()) {
    // Resolve path with CWD support
    std::string resolved = resolve_path(iso_target);
    if (resolved.empty()) {
      log_error("File not found: " + iso_target);
      log_info("Resolved path was: " + iso_target);
      return 1;
    }
    log_info("Resolved: " + iso_target + " -> " + resolved);
    iso_target = resolved;
  }

  WindowsMountOptions win_opts = {};
  win_opts.enabled = false;
  win_opts.version = WindowsVersion::NONE;
  win_opts.use_usb3 = use_usb3;
  win_opts.has_uefi = false;
  win_opts.has_legacy = false;

  // Auto-detect Windows ISO if not forcing HDD mode
  if (!iso_target.empty() && !force_hdd) {
    // Check if it's a Windows ISO
    WindowsIsoInfo iso_info = get_windows_iso_info(iso_target);
    
    if (iso_info.is_windows || windows_mode) {
      win_opts.enabled = true;
      
      // Use detected info unless overridden
      if (force_win11) {
        win_opts.version = WindowsVersion::WIN11;
      } else if (force_win10) {
        win_opts.version = WindowsVersion::WIN10;
      } else if (iso_info.is_windows) {
        win_opts.version = iso_info.version;
      } else {
        win_opts.version = WindowsVersion::WIN_UNKNOWN;
      }
      
      win_opts.has_uefi = iso_info.has_uefi;
      win_opts.has_legacy = iso_info.has_legacy;
      
      // If we detected Windows, show info
      if (iso_info.is_windows && !windows_mode) {
        log_info("Windows ISO detected: " + iso_info.volume_label);
        log_info("Auto-enabling Windows mode.");
      }
    } else if (!is_hybrid_iso(iso_target) && !cdrom) {
      // Non-hybrid, non-Windows ISO - still use CD-ROM mode
      log_info("Non-hybrid ISO detected. Mounting as CD-ROM.");
      cdrom = true;
    }
  }

  bool success = false;

  if (force_configfs) {
    success = configs(iso_target, cdrom, ro, win_opts);
  }
  else if (force_usbgadget) {
    if (win_opts.enabled) {
       log_warn("Windows mode is only supported with configfs backend");
    }
    success = usb(iso_target, cdrom, ro);
  }
  else if (supported()) {
    success = configs(iso_target, cdrom, ro, win_opts);
  }
  else if (usb_supported()) {
    if (win_opts.enabled) {
       log_warn("Windows mode is only supported with configfs backend");
    }
    success = usb(iso_target, cdrom, ro);
  }
  else {
    log_error("Device does not support isodrive");
    return 1;
  }

  return success ? 0 : 1;
}

