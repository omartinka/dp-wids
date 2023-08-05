# Compiler
CC = gcc

# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build

# Files
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC_FILES))
MAIN_FILE = main.c

# Flags
CFLAGS = -I$(INCLUDE_DIR)

# Targets
EXECUTABLE = wids-sensor

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJ_FILES) $(MAIN_FILE:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(MAIN_FILE:.c=.o): $(MAIN_FILE)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(EXECUTABLE) $(MAIN_FILE:.c=.o)

.PHONY: all clean
