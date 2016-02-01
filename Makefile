include common/build.mk

ARCH := LINUX

ifeq ($(ARCH), ARM)
	AR = arm-none-linux-gnueabi-ar
	CC = arm-none-linux-gnueabi-gcc
else ifeq ($(ARCH), LINUX)
	AR = ar
	CC = gcc
endif

CFLAGS += -O3 -g -Wall -Werror -Wno-unused-function

%.o: %.c
	$(CC) $(LDFLAGS) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(CC) -shared $(CFLAGS) -o $(TARGET) $(OBJECTS)


decoder: decoder.o $(TARGET)
	$(CC) $(CFLAGS) -lm -o $@ $^
	rm -f *.o common/*.o

all: decoder

clean:
	rm -f decoder common/*.so common/*.o

