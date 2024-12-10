ifeq ($(OS), Windows_NT)
	CFLAGS:=-Os -DNDEBUG -ffunction-sections -fdata-sections -Wno-incompatible-pointer-types
	LDFLAGS:=-lkernel32 -luser32 -liphlpapi -lws2_32 -Wl,--gc-sections
	TARGET=my_dns.exe
else
	CFLAGS:=-Os -DNDEBUG -ffunction-sections -fdata-sections
	TARGET=my_dns
endif

SOURCE:=my_dns.c

$(info "CC     = $(CC)")
$(info "OS     = $(OS)")
$(info "CFLAGS = $(CFLAGS)")
$(info "LDFLAGS = $(LDFLAGS)")
$(info "SOURCE = $(SOURCE)")
$(info "TARGET = $(TARGET)")

all: $(TARGET)

$(TARGET):
	$(CC) $(SOURCE) $(CFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f *.o $(TARGET) || true

run: $(TARGET)
ifeq ($(OS), Windows_NT)
	.\$(TARGET) --query A baidu.com
else
	./$(TARGET) --query A baidu.com
endif

.PHONY: all clean

