TARGET = common/libcommon.so
LDFLAGS += -fPIC

SOURCES = $(shell echo common/*.c)
HEADERS = $(shell echo common/*.h)
OBJECTS = $(SOURCES:.c=.o)

