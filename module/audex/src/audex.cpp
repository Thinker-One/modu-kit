#include <spdlog.hpp>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <cstring>
#include <unistd.h>
#include <linux/audit.h>
#include "audex.hpp"
#include "common.hpp"

#define AUDIT_USER_AUTH         1100
#define AUDIT_USER_LOGIN	    1112
#define AUDIT_USER_LOGOUT	    1113
#define AUDIT_USER_END          1106

AuditCollector::AuditCollector() : netlink_socket_fd_(-1), is_running_(true) {

}

AuditCollector::~AuditCollector() {
    is_running_ = false;
    if (netlink_socket_fd_ >= 0) {
        close(netlink_socket_fd_);
        netlink_socket_fd_ = -1;
    }
    // 清理 audit 规则
    CommonTool::run_cmd("auditctl -d always,exit -F arch=b64 -S init_module -S finit_module -k mod_add_");
    CommonTool::run_cmd("auditctl -d always,exit -F arch=b64 -S delete_module -k mod_rm_");
}

void AuditCollector::start() {
    get_audit_event();
}

void AuditCollector::get_audit_event() {
    netlink_socket_fd_ = socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
    if (netlink_socket_fd_ < 0) {
        LOG_ERROR("socket error");
        return;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    addr.nl_groups = 1;//AUDIT_NLGRP_READLOG;

    if (bind(netlink_socket_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("bind netlink socket failed");
        close(netlink_socket_fd_);
        netlink_socket_fd_ = -1;
        return;
    }

    CommonTool::run_cmd("auditctl -a always,exit -F arch=b64 -S init_module -S finit_module -k mod_add_");
    CommonTool::run_cmd("auditctl -a always,exit -F arch=b64 -S delete_module -k mod_rm_");

    while (is_running_.load()) {
        struct sockaddr_nl nladdr;
        struct iovec iov = { recv_buffer_, sizeof(recv_buffer_) };
        struct msghdr msg = { &nladdr, sizeof(nladdr), &iov, 1, nullptr, 0, 0 };

        int len = recvmsg(netlink_socket_fd_, &msg, 0);
        if (len < 0) {
            LOG_ERROR("Netlink recvmsg error");
            continue;
        }

        for (struct nlmsghdr *nh = (struct nlmsghdr *)recv_buffer_; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {

            switch (nh->nlmsg_type) {
                case NLMSG_ERROR: {
                    LOG_ERROR("Netlink error");
                    continue;
                }

                case AUDIT_USER_AUTH:
                case AUDIT_USER_LOGIN: {
                    LOG_INFO("登录");
                    break;
                }

                case AUDIT_USER_LOGOUT:
                case AUDIT_USER_END: {
                    LOG_INFO("退出");
                    break;
                }

                case AUDIT_SYSCALL: {
                    const char* data_ptr = static_cast<const char*>(NLMSG_DATA(nh));
                    size_t data_len = nh->nlmsg_len - NLMSG_HDRLEN;
                    if (data_len == 0) break;

                    uint64_t serial = extract_audit_serial(data_ptr, data_len);
                    if (serial == 0) break;

                    // 查找 key 字段，避免多次搜索
                    const char* key_pos = find_in_payload(data_ptr, data_len, "key=\"", 5);
                    if (!key_pos) break;

                    key_pos += 5; // 跳过 "key=\""
                    const char* key_end = static_cast<const char*>(memchr(key_pos, '"', data_len - (key_pos - data_ptr)));
                    if (!key_end) break;

                    size_t key_len = key_end - key_pos;

                    if (key_len == 8 && memcmp(key_pos, "mod_add_", 8) == 0) {
                        LOG_INFO("驱动加载");
                    } else if (key_len == 7 && memcmp(key_pos, "mod_rm_", 7) == 0) {
                        LOG_INFO("驱动卸载");
                    } else if (key_len == 9 && memcmp(key_pos, "proc_rpm_", 9) == 0) {
                        event_cache_[serial].info.append(data_ptr, data_len);
                        event_cache_[serial].key.assign(key_pos, key_len);
                    }
                    break;
                }

                case AUDIT_EXECVE: {
                    const char* data_ptr = static_cast<const char*>(NLMSG_DATA(nh));
                    size_t data_len = nh->nlmsg_len - NLMSG_HDRLEN;
                    if (data_len == 0) break;

                    uint64_t serial = extract_audit_serial(data_ptr, data_len);
                    if (serial == 0) break;

                    std::string arg1;
                    bool is_rpm_event = false;

                    auto it = event_cache_.find(serial);
                    if (it == event_cache_.end()) break;
                    is_rpm_event = (it->second.key == "proc_rpm_");

                    if (is_rpm_event && extract_arg(data_ptr, data_len, "a1", arg1)) {
                        // 检查是否为查询操作（跳过）
                        if (arg1.find('q') != std::string::npos || arg1.find('V') != std::string::npos) {
                            event_cache_.erase(serial);
                            break;
                        }

                        // 检查是否为安装操作
                        bool is_install = (arg1.find('i') != std::string::npos ||
                                          arg1.find('U') != std::string::npos ||
                                          arg1.find('F') != std::string::npos ||
                                          arg1.find("--install") != std::string::npos ||
                                          arg1.find("--upgrade") != std::string::npos ||
                                          arg1.find("--freshen") != std::string::npos);

                        if (is_install) {
                            LOG_INFO("软件安装");
                        }

                        // 清理已处理的缓存
                        event_cache_.erase(serial);
                    }
                    break;
                }

                default: {
                    break;
                }
            }
        }

        // 定期清理过期缓存（每处理 100 条消息清理一次）
        static int msg_count = 0;
        if (++msg_count >= 100) {
            msg_count = 0;
            cleanup_old_cache();
        }
    }

    close(netlink_socket_fd_);
    netlink_socket_fd_ = -1;
}

uint64_t AuditCollector::extract_audit_serial(const char* data, size_t len) {
    if (!data || len == 0) return 0;

    const char* audit_start = (const char*)memmem(data, len, "audit(", 6);
    if (!audit_start) return 0;

    const char* search_limit = data + len;
    const char* colon = (const char*)memchr(audit_start, ':', search_limit - audit_start);
    
    if (colon && colon + 1 < search_limit) {
        char* endptr = nullptr;
        uint64_t serial = strtoull(colon + 1, &endptr, 10);
        
        if (endptr == colon + 1) return 0;
        return serial;
    }

    return 0;
}

const char* AuditCollector::find_in_payload(const char* data, size_t len, const char* needle, size_t needle_len) const {
    if (!data || !needle || needle_len == 0) return nullptr;
    return static_cast<const char*>(memmem(data, len, needle, needle_len));
}

bool AuditCollector::extract_arg(const char* data, size_t len, const char* arg_name, std::string& out) {
    if (!data || !arg_name) return false;

    // 构造搜索模式 "arg_name="
    char pattern[32];
    int pattern_len = snprintf(pattern, sizeof(pattern), "%s=", arg_name);
    if (pattern_len <= 0 || pattern_len >= static_cast<int>(sizeof(pattern))) return false;

    const char* pos = static_cast<const char*>(memmem(data, len, pattern, pattern_len));
    if (!pos) return false;

    const char* value_start = pos + pattern_len;
    const char* data_end = data + len;
    if (value_start >= data_end) return false;

    // 处理带引号的值
    if (*value_start == '"') {
        value_start++;
        const char* value_end = static_cast<const char*>(memchr(value_start, '"', data_end - value_start));
        if (value_end) {
            out.assign(value_start, value_end - value_start);
            return true;
        }
    } else {
        // 处理不带引号的值
        const char* value_end = value_start;
        while (value_end < data_end && *value_end != ' ' && *value_end != '\n' && *value_end != '\r') {
            value_end++;
        }
        out.assign(value_start, value_end - value_start);
        return true;
    }

    return false;
}

void AuditCollector::cleanup_old_cache() {

    // 如果缓存超过 1000 条，清空（简单策略）
    // 更复杂的可以基于时间戳或 LRU
    if (event_cache_.size() > 1000) {
        event_cache_.clear();
    }
}