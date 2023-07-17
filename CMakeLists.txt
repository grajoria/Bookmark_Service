cmake_minimum_required(VERSION 3.12)
project(BookmarkService)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Find the required libraries
find_package(SQLite3 REQUIRED)
find_package(Pistache REQUIRED)

# Add the include directories
include_directories(${Pistache_INCLUDE_DIRS})

# Add the executable for your project
add_executable(bookmark_service bookmark_service.cpp)

# Link the required libraries
target_link_libraries(bookmark_service PRIVATE ${Pistache_LIBRARIES} SQLite::SQLite3)
