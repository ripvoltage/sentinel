CC ?= gcc
CLANG ?= clang

CFLAGS ?= -std=c99 -D_GNU_SOURCE -O2 \
          -Wall -Wextra -Wpedantic \
          -Wformat=2 -Wformat-security -Werror=format-security \
          -D_FORTIFY_SOURCE=2 \
          -fstack-protector-strong \
          -fstack-clash-protection \
          -fcf-protection=full \
          -fPIE \
          -Iinclude

LDFLAGS ?= -pie \
           -Wl,-z,relro,-z,now \
           -Wl,-z,noexecstack \
           -lm -lpthread -ldl

BIN_DIR = bin
BUILD_DIR = build
SRC_DIR = src

SRCS = $(SRC_DIR)/entropy.c \
       $(SRC_DIR)/canaries.c \
       $(SRC_DIR)/heuristics.c \
       $(SRC_DIR)/proc_inspector.c \
       $(SRC_DIR)/defense.c \
       $(SRC_DIR)/cow_remediation.c \
       $(SRC_DIR)/notification.c \
       $(SRC_DIR)/logger.c \
       $(SRC_DIR)/ebpf_loader.c \
       $(SRC_DIR)/monitor.c

OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
MAIN_OBJ = $(BUILD_DIR)/main.o

TARGET = $(BIN_DIR)/sentinel
TEST_TARGET = $(BIN_DIR)/test_suite
TESTER_TARGET = $(BIN_DIR)/canary_tester

.PHONY: all clean test bpf install

all: $(TARGET) $(TESTER_TARGET)

$(TARGET): $(OBJS) $(MAIN_OBJ) | $(BIN_DIR)
	$(CC) $(OBJS) $(MAIN_OBJ) $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_suite.o: tests/test_suite.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/canary_tester.o: tools/canary_tester.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_TARGET): $(OBJS) $(BUILD_DIR)/test_suite.o | $(BIN_DIR)
	$(CC) $(OBJS) $(BUILD_DIR)/test_suite.o $(LDFLAGS) -o $@

$(TESTER_TARGET): $(BUILD_DIR)/canary_tester.o | $(BIN_DIR)
	$(CC) $(BUILD_DIR)/canary_tester.o $(LDFLAGS) -o $@

test: $(TEST_TARGET)
	@echo "Running Sentinel test suite..."
	@./$(TEST_TARGET)

bpf:
	@if command -v $(CLANG) >/dev/null 2>&1; then \
		echo "Compiling eBPF kernel object..."; \
		$(CLANG) -target bpf -O2 -g -c ebpf/sentinel.bpf.c -o $(BIN_DIR)/sentinel-ebpf.o; \
	else \
		echo "Clang not available on this system. Skipping eBPF bytecode compilation."; \
	fi

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

install: $(TARGET)
	install -d /usr/local/bin
	install -m 755 $(TARGET) /usr/local/bin/sentinel
	install -d /var/log/ransomware-detector
	install -d /usr/lib/sentinel
	@if [ -f $(BIN_DIR)/sentinel-ebpf.o ]; then \
		install -m 644 $(BIN_DIR)/sentinel-ebpf.o /usr/lib/sentinel/sentinel-ebpf.o; \
	fi
