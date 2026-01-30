# Makefile for OTP Generator

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -fstack-protector-strong -I/usr/include/node
LDFLAGS = -L/usr/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3

# Try to find OpenCV
OPENCV_FOUND := $(shell pkg-config --exists opencv4 && echo "yes" || pkg-config --exists opencv && echo "yes" || echo "no")

ifeq ($(OPENCV_FOUND),yes)
    OPENCV_CFLAGS := $(shell pkg-config --cflags opencv4 2>/dev/null || pkg-config --cflags opencv 2>/dev/null)
    OPENCV_LIBS := $(shell pkg-config --libs opencv4 2>/dev/null || pkg-config --libs opencv 2>/dev/null)
    CXXFLAGS += $(OPENCV_CFLAGS) -DHAVE_OPENCV
    LDFLAGS += $(OPENCV_LIBS)
    QR_SOURCE = QRGenerator.cpp
    $(info Building with OpenCV support)
else
    QR_SOURCE = QRGenerator_noopencv.cpp
    $(info Building without OpenCV - QR codes will show URI only)
endif

TARGET = otp
SOURCES = main.cpp OTPGenerator.cpp $(QR_SOURCE)
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete! Executable: ./$(TARGET)"

%.o: %.cpp
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
	@echo "Clean complete"

install-deps:
	@echo "Please install dependencies manually:"
	@echo "  sudo apt-get install libopencv-dev libssl-dev"

test: $(TARGET)
	@echo "Running help command..."
	./$(TARGET) --help

.PHONY: all clean install-deps test
