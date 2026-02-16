#ifndef NETWORKSERVER_H
#define NETWORKSERVER_H

#include <string>
#include <vector>

/**
 * @file networkserver.h
 * @brief Network sharing server for ISO/IMG files.
 * 
 * Provides support for sharing ISO/IMG files over the network using
 * multiple protocols: SMB, HTTP (iPXE), iSCSI, and NetBoot (DHCP+TFTP+HTTP).
 */

/**
 * @enum NetworkProtocol
 * @brief Supported network sharing protocols.
 */
enum class NetworkProtocol {
    NONE = 0,   ///< No protocol selected
    SMB,        ///< SMB/CIFS (Windows file sharing) - NOT bootable
    HTTP,       ///< HTTP Server (iPXE) - BOOTABLE
    ISCSI,      ///< iSCSI (Network Block Device) - BOOTABLE
    NETBOOT     ///< NetBoot (DHCP+TFTP+HTTP) - BOOTABLE - Full network boot
};

/**
 * @struct NetworkShareOptions
 * @brief Configuration options for network sharing.
 */
struct NetworkShareOptions {
    NetworkProtocol protocol;      ///< Protocol to use
    std::string share_name;        ///< Share name (for SMB)
    std::string username;          ///< Username for SMB authentication
    std::string password;          ///< Password for SMB authentication
    std::vector<std::string> paths;///< Files to share
    uint16_t port;                 ///< Port to listen on (default: varies by protocol)
    bool read_only;                ///< Read-only access
    std::string ip_address;        ///< Specific IP to bind to (empty = all interfaces)
};

/**
 * @brief Check if SMB server (smbd) is available on the system.
 * 
 * @return true if smbd is available, false otherwise.
 */
bool has_smb_server();

/**
 * @brief Check if a simple HTTP server can be started (built-in).
 * 
 * @return true always (built-in server), false on error.
 */
bool has_http_server();

/**
 * @brief Check if iSCSI target daemon is available on the system.
 * 
 * @return true if target daemon is available, false otherwise.
 */
bool has_iscsi_target();

/**
 * @brief Check if dnsmasq is available on the system.
 * 
 * @return true if dnsmasq is available, false otherwise.
 */
bool has_dnsmasq();

/**
 * @brief Start network sharing with the specified options.
 * 
 * Starts a server using the specified protocol to share the given files.
 * 
 * @param options Network sharing configuration.
 * @return true if server started successfully, false on error.
 */
bool start_network_share(const NetworkShareOptions& options);

/**
 * @brief Stop the currently running network share server.
 * 
 * Stops any active network sharing server.
 * 
 * @return true if stopped successfully, false on error.
 */
bool stop_network_share();

/**
 * @brief Check if a network share is currently active.
 * 
 * @return true if a network share is running, false otherwise.
 */
bool is_network_share_active();

/**
 * @brief Get the current network share status information.
 * 
 * Returns a string with status info including protocol, port, and shared files.
 * 
 * @return Status string, or empty if no share is active.
 */
std::string get_network_share_status();

/**
 * @brief Get the IP address of the device on the network.
 * 
 * Attempts to get the IP address from the default network interface.
 * 
 * @return IP address string, or empty if not available.
 */
std::string get_local_ip_address();

/**
 * @brief Convert NetworkProtocol enum to human-readable string.
 * 
 * @param protocol The NetworkProtocol value.
 * @return String representation (e.g., "SMB", "HTTP", "iSCSI", "NetBoot").
 */
std::string network_protocol_to_string(NetworkProtocol protocol);

#endif // ifndef NETWORKSERVER_H
