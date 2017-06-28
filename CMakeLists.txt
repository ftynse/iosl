project(iosl)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

set(CMAKE_BUILD_TYPE Debug)

target_link_libraries(${PROJECT_NAME} isl)
target_link_libraries(${PROJECT_NAME} osl)
target_link_libraries(${PROJECT_NAME} pet)
