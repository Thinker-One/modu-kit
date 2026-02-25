#ifndef FILE_WATCHER_HPP
#define FILE_WATCHER_HPP

#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <unordered_set>


#define MAX_BUFFER_SIZE 4096

class FileWatcher {
public:
    using Callback = std::function<void(std::chrono::steady_clock::time_point, const std::string &)>;
    using DirMap = std::unordered_map<std::string, std::unordered_set<std::string>>;
    enum class FileType {
        REGULAR_FILE,
        DIRECTORY,
        SYMLINK,
        BLOCK_DEVICE,
        CHARACTER_DEVICE,
        FIFO,
        SOCKET,
        UNKNOWN,
        NOT_EXIST
    };

    struct MonObjInfo {
        std::string name;
        FileType type;
    };

    FileWatcher();
    ~FileWatcher();
    bool init();
    int start();
    int stop();

public:
    void print_inotify_dir_info();

private:
    static void split_path(const std::string& full, std::string& dir, std::string& file);
    void run();
    bool is_vim_noise(const std::string& filename);
    void get_inotify_dir();
    uint32_t get_event_mask(const FileType type);
    void handle_event(std::chrono::steady_clock::time_point now, const std::string &str);
    bool is_monitor_obj(std::string dir, std::string filename);

private:
    int inotify_fd_;
    std::unordered_map<int, MonObjInfo> watch_descs_;
    std::unordered_set<std::string> already_inotify_dirs_;
    std::atomic<bool> running_;
    std::thread watch_thread_;
    std::string target_path_;
    std::string dir_path_;
    std::string filename_;
    Callback callback_;
    std::mutex mutex_;
    std::chrono::steady_clock::time_point last_trigger_time_;
    DirMap dirs_;
};


#endif