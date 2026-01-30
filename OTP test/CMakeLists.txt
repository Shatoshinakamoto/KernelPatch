cmake_minimum_required(VERSION 3.15)
project(otp_generator)

set(CMAKE_CXX_STANDARD 17)

add_executable(otp_generator src/main.cpp)

# Find and link required libraries for QR code and encryption
# Example: find_package(OpenSSL REQUIRED)
# target_link_libraries(otp_generator OpenSSL::SSL)
# Add more as needed
