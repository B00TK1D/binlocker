CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -s
TARGET = binlocker

all: $(TARGET)

$(TARGET): binlocker.c
	$(CC) $(CFLAGS) -o $(TARGET) binlocker.c

clean:
	rm -f $(TARGET) test_binary test_binary_protected /tmp/binlocker_stub.c

test: $(TARGET)
	@echo "Creating test binary..."
	@echo '#!/bin/bash' > test_binary
	@echo 'echo "Hello from protected binary!"' >> test_binary
	@echo 'echo "Arguments: $$@"' >> test_binary
	@chmod +x test_binary
	@echo "Protecting test binary with password 'secret123'..."
	@./$(TARGET) test_binary secret123
	@echo "Testing protected binary..."
	@./test_binary_protected secret123 arg1 arg2

.PHONY: all clean test
