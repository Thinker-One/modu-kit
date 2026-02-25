#ifndef COMMON_HPP
#define COMMON_HPP
#include <vector>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

// key->dir     value->filename
using DirMap = std::unordered_map<std::string, std::unordered_set<std::string>>;
// using DirMap = std::vector<std::pair<std::string, std::string>>;
namespace CommonTool {
    
    enum class PathType {
        NOT_FOUND,
        REGULAR_FILE,
        DIRECTORY,
        OTHER                   // 如管道、设备文件等
    };

    struct PathInfo {
        bool is_symlink;
        std::string real_path;
        PathType type;
    };

    struct CmdResult {
        std::string output;
        int exit_code;
    };

    void create_dir_recurise(const std::string &path);
    PathInfo analyze_path(const std::string &path);
    PathType get_type_from_stat(const struct stat &st);
    CmdResult run_cmd(const std::string &cmd);
    void get_user_startup_dirs(DirMap &dirs);
}

#endif