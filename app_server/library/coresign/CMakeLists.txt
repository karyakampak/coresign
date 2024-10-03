cmake_minimum_required(VERSION 3.2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

project(coresign)

# Define the shared library
add_library(coresign_library SHARED
    src/addons.cpp
    src/main.cpp
)

add_executable(coresign_executable
    src/addons.cpp
    src/main.cpp
)


find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(coresign_executable ${OPENSSL_LIBRARIES})
target_link_libraries(coresign_library ${OPENSSL_LIBRARIES})

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})
target_link_libraries(coresign_executable ${CURL_LIBRARIES})
target_link_libraries(coresign_library ${CURL_LIBRARIES})

# Determine platform-specific include and lib directories
if(APPLE)
    set(INCLUDE_DIR "/usr/local/opt/coresign/include")
    set(LIB_DIR "/usr/local/opt/coresign/lib")
    set(BIN_DIR "/usr/local/opt/coresign/bin")
    set(OTHER_DIR "/usr/local/opt/coresign")
elseif(UNIX)
    set(INCLUDE_DIR "/usr/include/coresign")
    set(LIB_DIR "/usr/lib/coresign")
    set(BIN_DIR "/usr/bin/coresign")
    set(OTHER_DIR "/usr/include/coresign")
else()
    message(FATAL_ERROR "Unsupported platform")
endif()


# Optionally, install the executable to the "bin" folder after building
install(TARGETS coresign_executable DESTINATION bin)

install(FILES
    build/bin/coresign
    DESTINATION ${BIN_DIR}
)

install(TARGETS coresign_library
    LIBRARY DESTINATION ${LIB_DIR}
)

install(FILES
    header/sign.h
    header/addons.h
    DESTINATION ${INCLUDE_DIR}
)

install(FILES
    LICENSE.txt
    README.md
    AUTHORS.md
    DESTINATION ${OTHER_DIR}
)

set_target_properties(coresign_library PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

set_target_properties(coresign_executable PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

set_target_properties(coresign_library coresign_executable PROPERTIES OUTPUT_NAME coresign)

# Set compiler flags if needed
# target_compile_options(besign PRIVATE -Wall -Wextra)

# Set compiler features if needed
# target_compile_features(besign PUBLIC cxx_std_11)