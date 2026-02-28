#include <chrono>
#include <thread>
#include <spdlog.hpp>
#include "audex.hpp"

int main() {
    AuditCollector audit_prase_obj;
    audit_prase_obj.start();
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return 0;
}