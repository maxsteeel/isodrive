#include "androidusbisomanager.h"
#include "configfsisomanager.h"
#include "logger.h"
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
            << "\t\t   -exfat\t Formats as exFAT (requires mkfs.exfat).\n\n"
            << "Backend options:\n"
            << "-configfs\t Forces the app to use configfs.\n"
            << "-usbgadget\t Forces the app to use sysfs.\n\n"
            << "Output options:\n"
            << "-v, -verbose\t Enables verbose/debug output.\n"
            << "-q, -quiet\t Suppresses all output except errors.\n\n";
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
                        bool dynamic, bool rw, const std::string& format_type) {
  uint64_t size = 0;
  
  if (!parse_size_string(size_str, &size)) {
    log_error("Invalid size format: " + size_str);
    log_info("Valid formats: 2GB, 500MB, 1TB, 1024KB, etc.");
    return false;
  }
  
  bool success = create_img_file(img_path, size, dynamic, !rw);
  if (!success) {
    return false;
  }
  
  if (!format_type.empty()) {
    success = format_img_file(img_path, format_type);
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
  std::string create_path;
  std::string create_size;
  bool create_dynamic = false;
  bool create_rw = false;
  std::string create_format;
  
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

  if (create_mode) {
    if (create_path.empty() || create_size.empty()) {
      log_error("Missing arguments for -create");
      log_info("Usage: -create [path] [size] [options]");
      log_info("Example: -create example.img 2GB -dynamic -rw");
      return 1;
    }
    
    return handle_create_mode(create_path, create_size, create_dynamic, create_rw, create_format) ? 0 : 1;
  }

  if (force_win10 && force_win11) {
    log_error("Incompatible arguments -win10 and -win11");
    return 1;
  }

  if (multi_mode) {
    if (iso_targets.empty()) {
      log_info("No files specified, unmounting all ISOs...");
    } else {
      for (size_t i = 0; i < iso_targets.size(); i++) {
        if (!isfile(iso_targets[i])) {
          log_error("File not found: " + iso_targets[i]);
          return 1;
        }
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
      for (size_t i = 0; i < iso_targets.size(); i++) {
        WindowsIsoInfo iso_info = get_windows_iso_info(iso_targets[i]);
        
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
            log_info("Windows ISO detected: " + iso_targets[i]);
            log_info("Auto-enabling Windows mode.");
          }
        } else if (!force_hdds.empty() && !force_hdds[i]) {
          if (!is_hybrid_iso(iso_targets[i])) {
            if (i >= cdroms.size()) {
              cdroms.push_back(true);
            } else {
              cdroms[i] = true;
            }
            log_info("Non-hybrid ISO detected: " + iso_targets[i] + ", using CD-ROM mode");
          }
        } else if (!is_hybrid_iso(iso_targets[i])) {
          if (i >= cdroms.size()) {
            cdroms.push_back(true);
          } else {
            cdroms[i] = true;
          }
          log_info("Non-hybrid ISO detected: " + iso_targets[i] + ", using CD-ROM mode");
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

  if (!iso_target.empty() && !isfile(iso_target)) {
    log_error("File not found: " + iso_target);
    return 1;
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
