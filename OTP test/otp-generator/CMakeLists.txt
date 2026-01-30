cmake_minimum_required(VERSION 3.10)
project(OTPGenerator)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenCV REQUIRED)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(
    ${OpenCV_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Source files
set(SOURCES
    main.cpp
    OTPGenerator.cpp
    QRGenerator.cpp
)

# Create executable
add_executable(otp ${SOURCES})

# Link libraries
target_link_libraries(otp 
    ${OpenCV_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Compiler flags for security
target_compile_options(otp PRIVATE
    -Wall
    -Wextra
    -O2
    -fstack-protector-strong
)

# Set output directory
set_target_properties(otp PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Print configuration info
message(STATUS "OpenCV version: ${OpenCV_VERSION}")
message(STATUS "OpenCV libraries: ${OpenCV_LIBRARIES}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
