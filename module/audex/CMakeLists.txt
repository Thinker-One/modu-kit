cmake_minimum_required(VERSION 3.14)
project(audex LANGUAGES CXX)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 指定源文件路径
file(GLOB SRC_FILES 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/*.cpp
)

# 指定可执行程序
add_executable(audex ${SRC_FILES})

# 设置编译参数
target_compile_options(audex PRIVATE
    -Wall 
    -Wextra 
    # -Wpedantic
    # 使用生成器表达式，针对不同模式自动切换
    $<$<CONFIG:Debug>: -O0 -g -Werror>
    $<$<CONFIG:Release>: -O3 -march=native>
)

# 链接库
target_link_libraries(audex PRIVATE
    pthread
    udev
)

# 宏定义
target_compile_definitions(audex PRIVATE
    $<$<CONFIG:Release>:LOG_TO_FILE_ENABLED=1>
    $<$<CONFIG:Debug>:SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG>
    $<$<CONFIG:Debug>:STDOUT_ENABLED=1>
)

# 指定头文件路径
target_include_directories(audex PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../common/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(audex SYSTEM PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../common/third_party/spdlog/include
)
# if (CMAKE_BUILD_TYPE STREQUAL "Debug")
#     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wpedantic")
# endif()

