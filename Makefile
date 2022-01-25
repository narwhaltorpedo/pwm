CC := gcc
STANDARD_CC_FLAGS := \
	-Werror \
	-Wall \
	-Wcast-align \
	-Wstrict-prototypes \
	-Wformat-truncation=0
ARGON_SRC := ./phc-winner-argon2
CHA_CHA_SRC := ./libtomcrypt/src
SRC_FILES := $(wildcard ./*.c) \
			 $(wildcard $(ARGON_SRC)/src/argon2.c) \
			 $(wildcard $(ARGON_SRC)/src/core.c) \
			 $(wildcard $(ARGON_SRC)/src/encoding.c) \
			 $(wildcard $(ARGON_SRC)/src/ref.c) \
			 $(wildcard $(ARGON_SRC)/src/thread.c) \
			 $(wildcard $(ARGON_SRC)/src/blake2/*.c) \
			 $(wildcard $(CHA_CHA_SRC)/stream/chacha/*.c) \
			 $(wildcard $(CHA_CHA_SRC)/encauth/chachapoly/*.c) \
			 $(wildcard $(CHA_CHA_SRC)/mac/poly1305/*.c) \
			 $(CHA_CHA_SRC)/misc/crypt/crypt_argchk.c \
			 $(CHA_CHA_SRC)/misc/mem_neq.c \
			 $(CHA_CHA_SRC)/misc/zeromem.c
INCLUDES := -I . -I $(ARGON_SRC)/include -I $(ARGON_SRC)/src -I $(ARGON_SRC)/src/blake2 \
            -I $(CHA_CHA_SRC)/headers
LIBRARIES := -lpthread
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
	-$(CC) $(SRC_FILES) $(STANDARD_CC_FLAGS) $(INCLUDES) $(LIBRARIES) -o $(BUILD_DIR)/$(EXE_FILE)

.PHONY: clean
clean:
	rm -rf build