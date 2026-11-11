# Makefile for secp256k1 JNI ECRECOVER implementation

# Directories
SECP256K1_DIR = ../bitcoin-core-secp256k1
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
LIB_DIR = $(BUILD_DIR)/lib

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O3 -fPIC -std=c99
INCLUDES = -I$(SECP256K1_DIR)/include -I$(SECP256K1_DIR)/src
JNI_INCLUDES = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/$(JNI_OS_DIR)
LDFLAGS = -shared
LDFLAGS_STATIC =
# linked into the shared library, so that it does not depend on a libsecp256k1 shared library
LIBS_STATIC = $(SECP256K1_DIR)/.libs/libsecp256k1.a

# Platform-specific settings. EXPORTS lists the symbols the shared library exports: the JNI and
# the plain C functions, not the API of the libsecp256k1 linked into it.
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    PLATFORM = darwin
    SHARED_EXT = dylib
    STATIC_EXT = a
    JNI_OS_DIR = darwin
    EXPORTS = exports-darwin.txt
    LDFLAGS += -Wl,-exported_symbols_list,$(EXPORTS)
else ifeq ($(UNAME_S),Linux)
    PLATFORM = linux-gnu
    SHARED_EXT = so
    STATIC_EXT = a
    JNI_OS_DIR = linux
    EXPORTS = exports-linux.map
    LDFLAGS += -Wl,-soname,libsecp256k1_ecrecover.$(SHARED_EXT) -Wl,--version-script=$(EXPORTS) -Wl,-z,defs
else
    $(error Unsupported platform: $(UNAME_S))
endif

ifeq ($(UNAME_M),x86_64)
    ARCH = x86_64
else ifeq ($(UNAME_M),aarch64)
    ARCH = aarch64
else ifeq ($(UNAME_M),arm64)
    ARCH = aarch64
else
    ARCH = $(UNAME_M)
endif

TARGET_DIR = $(BUILD_DIR)/$(PLATFORM)-$(ARCH)
TARGET_LIB_DIR = $(TARGET_DIR)/lib
TARGET_LIB = $(TARGET_LIB_DIR)/libsecp256k1_ecrecover.$(SHARED_EXT)
TARGET_STATIC_LIB = $(TARGET_LIB_DIR)/libsecp256k1_ecrecover.$(STATIC_EXT)
TARGET_HEADER = $(TARGET_LIB_DIR)/secp256k1_ecrecover.h

ifeq ($(JAVA_HOME),)
    $(error JAVA_HOME must be set to find jni.h)
endif

# Source files. The JNI glue only goes into the shared library, the static library for GraalVM
# native-image has the plain C functions only.
SOURCES = secp256k1_ecrecover.c
OBJECTS = $(SOURCES:%.c=$(OBJ_DIR)/%.o)
JNI_SOURCES = secp256k1_jni.c
JNI_OBJECTS = $(JNI_SOURCES:%.c=$(OBJ_DIR)/%.o)

# Default target
all: $(TARGET_LIB) $(TARGET_STATIC_LIB) $(TARGET_LIB_DIR)/libsecp256k1.a $(TARGET_HEADER) $(TARGET_LIB_DIR)/secp256k1.h $(TARGET_LIB_DIR)/secp256k1_recovery.h

# Create directories
$(OBJ_DIR) $(TARGET_LIB_DIR):
	mkdir -p $@

# Compile source files
$(OBJ_DIR)/%.o: %.c secp256k1_ecrecover.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(JNI_OBJECTS): INCLUDES += $(JNI_INCLUDES)

# Link shared library
$(TARGET_LIB): $(OBJECTS) $(JNI_OBJECTS) $(LIBS_STATIC) $(EXPORTS) | $(TARGET_LIB_DIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(JNI_OBJECTS) $(LIBS_STATIC)

# Create static library (JNI wrapper only, not including libsecp256k1.a)
$(TARGET_STATIC_LIB): $(OBJECTS) | $(TARGET_LIB_DIR)
	ar rcs $@ $(OBJECTS)

# Copy libsecp256k1.a from bitcoin-core-secp256k1
$(TARGET_LIB_DIR)/libsecp256k1.a: $(SECP256K1_DIR)/.libs/libsecp256k1.a | $(TARGET_LIB_DIR)
	cp $(SECP256K1_DIR)/.libs/libsecp256k1.a $@

# Copy header files
$(TARGET_HEADER): secp256k1_ecrecover.h | $(TARGET_LIB_DIR)
	cp secp256k1_ecrecover.h $@

# Copy bitcoin-core-secp256k1 headers
$(TARGET_LIB_DIR)/secp256k1.h: $(SECP256K1_DIR)/include/secp256k1.h | $(TARGET_LIB_DIR)
	cp $(SECP256K1_DIR)/include/secp256k1.h $@

$(TARGET_LIB_DIR)/secp256k1_recovery.h: $(SECP256K1_DIR)/include/secp256k1_recovery.h | $(TARGET_LIB_DIR)
	cp $(SECP256K1_DIR)/include/secp256k1_recovery.h $@

# Build secp256k1 dependency if needed
$(SECP256K1_DIR)/libsecp256k1.la:
	cd $(SECP256K1_DIR) && ./autogen.sh && ./configure --enable-module-recovery --with-pic --disable-shared && make

secp256k1: $(SECP256K1_DIR)/libsecp256k1.la

# Clean
clean:
	rm -rf $(BUILD_DIR)

# Rebuild
rebuild: clean all

# Test target (placeholder)
test: $(TARGET_LIB)
	@echo "Test target not implemented yet"

.PHONY: all clean rebuild test secp256k1

# Print build information
info:
	@echo "Platform: $(PLATFORM)"
	@echo "Architecture: $(ARCH)"
	@echo "Target library: $(TARGET_LIB)"
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"