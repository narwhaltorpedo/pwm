CC := gcc
STANDARD_CC_FLAGS := \
	-Werror \
	-Wall \
	-Wcast-align \
	-Wstrict-prototypes \
	-Wformat-truncation=0
SRC_FILES := $(wildcard ./*.c) \
			 $(wildcard ./libtomcrypt/src/stream/chacha/*.c) \
			 $(wildcard ./libtomcrypt/src/encauth/chachapoly/*.c) \
			 $(wildcard ./libtomcrypt/src/mac/poly1305/*.c) \
			 ./libtomcrypt/src/misc/crypt/crypt_argchk.c \
			 ./libtomcrypt/src/misc/mem_neq.c \
			 ./libtomcrypt/src/misc/zeromem.c
INCLUDES := -I . -I libtomcrypt/src/headers
BUILD_DIR := $(CURDIR)/build
EXE_FILE := pwm

# Setup the build.
define setupBuild
if [ ! -d $(BUILD_DIR) ]; then mkdir $(BUILD_DIR); fi
endef

# Build.
.PHONY: build
build:
	$(setupBuild)
	-$(CC) $(SRC_FILES) $(STANDARD_CC_FLAGS) $(INCLUDES) -o $(BUILD_DIR)/$(EXE_FILE)

.PHONY: clean
clean:
	rm -rf build