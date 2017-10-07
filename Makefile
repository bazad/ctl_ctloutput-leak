TARGET = ctl_ctloutput-leak

DEBUG   ?= NO
ARCH    ?= x86_64
SDK     ?= macosx

CLANG    := $(shell xcrun --sdk $(SDK) --find clang)
ifeq ($(CLANG),)
$(error Could not find clang for SDK $(SDK))
endif
SYSROOT  := $(shell xcrun --sdk $(SDK) --show-sdk-path)
CC       := $(CLANG) -isysroot $(SYSROOT) -arch $(ARCH)
CODESIGN := codesign

CFLAGS = -O2 -Wall -Werror -Wpedantic -Wno-gnu

ifeq ($(DEBUG),YES)
DEFINES += -DDEBUG=1
endif

FRAMEWORKS =

SOURCES = $(TARGET).c

HEADERS =

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(DEFINES) -o $@ $(SOURCES)
	$(CODESIGN) -s - $@

clean:
	rm -f -- $(TARGET)
