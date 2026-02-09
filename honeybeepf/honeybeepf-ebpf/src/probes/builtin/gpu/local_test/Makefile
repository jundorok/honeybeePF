CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -ldl -lpthread

.PHONY: all clean run test

all: libfake_nccl.so test_nccl_uprobe

libfake_nccl.so: fake_nccl.c
	$(CC) -shared -fPIC -o $@ $<
	@echo "✓ Built libfake_nccl.so"

test_nccl_uprobe: test_nccl_uprobe.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✓ Built test_nccl_uprobe"

run: all
	./test_nccl_uprobe ./libfake_nccl.so

test: all
	@echo "═══════════════════════════════════════════════════"
	@echo "  1. Start HoneyBeePF in another terminal:"
	@echo "     sudo ./honeybeepf --nccl-path $$(pwd)/libfake_nccl.so"
	@echo ""
	@echo "  2. Press Enter to run the test..."
	@echo "═══════════════════════════════════════════════════"
	@read _
	./test_nccl_uprobe ./libfake_nccl.so

clean:
	rm -f libfake_nccl.so test_nccl_uprobe