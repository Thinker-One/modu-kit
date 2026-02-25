#include <sys/inotify.h>
#include <spdlog.hpp>
#include "file_watcher.hpp"

FileWatcher::FileWatcher() :
    inotify_fd_(-1),
    running_(false),
    last_trigger_time_(std::chrono::steady_clock::now()) 
{}

FileWatcher::~FileWatcher() {
    stop();
}

bool FileWatcher::init() {
    if (running_) return false;
    running_ = true;
    dirs_.clear();
    watch_descs_.clear();
    already_inotify_dirs_.clear();

    inotify_fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd_ < 0) {
        LOG_ERROR("inotify_init1 failed.");
        return false;
    }

    get_inotify_dir();
    if (dirs_.empty()) {
        close(inotify_fd_);
        inotify_fd_ = -1;
        running_ = false;
        return false;
    }

    FileType type;
    std::string monitor_obj;

    for (auto &it : dirs_) {
        for (auto &fname : it.second) {
            if (fname.empty()) {
                type = FileType::DIRECTORY;
                monitor_obj = it.first;
                LOG_INFO("新增监控路径, DIR = {}", it.first);
            } else {
                type = FileType::REGULAR_FILE;
                monitor_obj = it.first + "/" + fname;
                LOG_INFO("新增监控文件, FILE = {}", monitor_obj);
            }
            
            int wd = inotify_add_watch (
                inotify_fd_,
                monitor_obj.c_str(),
                get_event_mask(type)
            );

            if (wd < 0) {
                LOG_ERROR("inotify_add_watch failed, monitor_obj={}", monitor_obj);
                continue;
            }
            watch_descs_[wd] = {monitor_obj, type};
        }
    }

    return true;
}

uint32_t FileWatcher::get_event_mask(const FileType type) {
    switch (type) {
        case FileType::REGULAR_FILE: {
            return IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF;
        }

        case FileType::DIRECTORY: {
            return IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_CLOSE_WRITE | IN_ATTRIB | IN_MODIFY;
        }

        default: {
            return 0;
        }
    }
}

int FileWatcher::start() {
    watch_thread_ = std::thread(&FileWatcher::run, this);
    return 0;
}

int FileWatcher::stop() {
    if (!running_.exchange(false)) return  -1;

    if (watch_thread_.joinable()) {
        watch_thread_.join();
    }

    if (inotify_fd_ >= 0) {
        close(inotify_fd_);
        inotify_fd_ = -1;
    }
    return 0;
}

void FileWatcher::split_path(const std::string& full, std::string& dir, std::string& file) {
    auto pos = full.find_last_of('/');
    if (pos == std::string::npos) {
        dir = ".";
        file = full;
    } else {
        dir = full.substr(0, pos);
        file = full.substr(pos + 1);
    }
}

bool FileWatcher::is_vim_noise(const std::string& filename) {
    if (filename.empty()) return false;

    if (filename.find_first_not_of("0123456789") == std::string::npos) {
        return true;
    }

    if (filename.back() == '~') {
        return true;
    }

    if (filename.size() > 4 && filename.front() == '.') {
        size_t last_dot = filename.find_last_of('.');
        if (last_dot != std::string::npos && last_dot > 0) {
            std::string ext = filename.substr(last_dot);
            if (ext.size() >= 4 && ext.compare(0, 3, ".sw") == 0) {
                return true;
            }
        }
    }

    return false;
}

void FileWatcher::run() {

    alignas(inotify_event) char buffer[MAX_BUFFER_SIZE];

    while (running_) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(inotify_fd_, &rfds);

        timeval tv{1, 0};
        int ret = select(inotify_fd_ + 1, &rfds, nullptr, nullptr, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("select 失败");
            break;
        }
        if (ret == 0) continue;


        ssize_t len = read(inotify_fd_, buffer, sizeof(buffer));
        if (len < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            break;
        }

        auto now = std::chrono::steady_clock::now();

        for (ssize_t i = 0; i < len; ) {
            if (i + (ssize_t)sizeof(inotify_event) > len) break;
            auto* ev = reinterpret_cast<inotify_event*>(&buffer[i]);
            if (i + (ssize_t)sizeof(inotify_event) + (ssize_t)ev->len > len) break;

            auto it = watch_descs_.find(ev->wd);
            if (it == watch_descs_.end()) {
                LOG_WARN("未知的 watch descriptor");
            } else {
                switch (it->second.type) {
                    case FileType::REGULAR_FILE: {
                        if (ev->mask & (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF)) {
                            handle_event_file(now ,ev->wd);
                        }
                        break;
                    }

                    case FileType::DIRECTORY: {
                        if (ev->len && !is_vim_noise(ev->name)) {
                            if (ev->mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB)) {
                                handle_event_dir(now, ev->name);
                            }
                        }
                        break;
                    }

                    default: {
                        LOG_WARN("未知的文件类型");
                    }
                }
            }
            i += sizeof(inotify_event) + ev->len;
        }
    }
}

bool FileWatcher::is_monitor_obj(std::string dir, std::string filename) {
    if (dir == "/etc" && filename != "crontab" && filename != "rc.local") {
        return false;
    } else if ((dir.substr(0, 6) == "/home/" || dir.substr(0, 6) == "/root") && \
                filename != ".bashrc" && filename != ".bash_profile" && \
                filename != ".profile" && filename != ".cshrc")
    {
        return false;
    }
    return true;
}

void FileWatcher::handle_event_dir(std::chrono::steady_clock::time_point now, const std::string &str) {

    std::lock_guard<std::mutex> lock(mutex_);
    if (now - last_trigger_time_ < std::chrono::milliseconds(500)) {
        return;
    }

    last_trigger_time_ = now;
    LOG_WARN("文件变动:={}", str);
}

void FileWatcher::handle_event_file(std::chrono::steady_clock::time_point now, int wd) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (now - last_trigger_time_ < std::chrono::milliseconds(500)) {
        return;
    }
    last_trigger_time_ = now;
    LOG_WARN("文件变动:={}", watch_descs_[wd].name);
}

void FileWatcher::get_inotify_dir() {
    std::vector<std::string> dirs = {
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
        "/etc/rc.d",
        "/etc/rc.local",
        "/etc/rc.d/rc0.d",
        "/etc/rc.d/rc1.d",
        "/etc/rc.d/rc2.d",
        "/etc/rc.d/rc3.d",
        "/etc/rc.d/rc4.d",
        "/etc/rc.d/rc5.d",
        "/etc/rc.d/rc6.d",
        "/etc/rc.d/init.d"
    };
    
    for (auto &d : dirs) {
        CommonTool::PathInfo info = CommonTool::analyze_path(d);
        if (info.type == CommonTool::PathType::REGULAR_FILE) {
            std::pair<std::string, std::string> new_dir;
            split_path(info.real_path, new_dir.first, new_dir.second);
            dirs_[new_dir.first].insert(new_dir.second);
        } else if (info.type == CommonTool::PathType::DIRECTORY) {
            dirs_[info.real_path].insert("");
        }
    }

    CommonTool::get_user_startup_dirs(dirs_);
}

void FileWatcher::print_inotify_dir_info() {
    for (auto &it : dirs_) {
        for (auto &fname : it.second) {
            LOG_INFO("dir={}, filename={}", it.first, fname);
        }
    }
}