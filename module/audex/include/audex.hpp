#ifndef AUDIT_PRASE_HPP
#define AUDIT_PRASE_HPP
#include <atomic>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <linux/netlink.h>

#define MAX_BUFFER_SIZE         8192

struct AuditEventInfo {
    std::string info;
    std::string key;
};

class AuditCollector {

public:
    AuditCollector();
    ~AuditCollector();

public:
    void start();

private:
    void get_audit_event();
    uint64_t extract_audit_serial(const char* data, size_t len);
    const char* find_in_payload(const char* data, size_t len, const char* needle, size_t needle_len) const;
    bool extract_arg(const char* data, size_t len, const char* arg_name, std::string& out);
    void cleanup_old_cache();

private:
    using EventQueue = std::vector<std::unordered_map<std::string, std::string>>;
    int netlink_socket_fd_;
    std::atomic<bool> is_running_;
    std::unordered_map<uint64_t, AuditEventInfo> event_cache_;
    alignas(NLMSG_ALIGNTO) char recv_buffer_[MAX_BUFFER_SIZE];
};

#endif