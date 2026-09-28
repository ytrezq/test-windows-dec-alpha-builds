# Windows AXP64 (DEC Alpha 64-bit) runtime.
#
#   make            everything: the host loader, the translator, the guest DLLs
#   make host       winhost.exe (x86-64 PE, runs under Wine) + axpemu
#   make guest      the AXP64 Win32 layer and the demo program
#   make run        build, then run the demo under Wine + Xvfb
#   make test       differential test of the translator against qemu-alpha
CC      = gcc
CFLAGS  = -O2 -g -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing -Isrc
LDFLAGS = -lm
MINGW   = x86_64-w64-mingw32-gcc
WINLIBS = -luser32 -lgdi32 -ladvapi32 -lshell32 -lcomdlg32 -lcomctl32
BUILD   = build

COMMON  = $(BUILD)/jit.o $(BUILD)/helpers.o

.PHONY: all host guest run test clean
all: host guest

host: $(BUILD)/axpemu $(BUILD)/winhost.exe

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c src/emu.h src/x86emit.h src/helpers.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD)/%.w64.o: src/%.c src/emu.h src/x86emit.h src/helpers.h | $(BUILD)
	$(MINGW) $(CFLAGS) -c -o $@ $<

# the standalone translator, for the differential test
$(BUILD)/axpemu: $(COMMON) $(BUILD)/main.o
	$(CC) -o $@ $^ $(LDFLAGS)

# the loader: an ordinary x86-64 Windows program.  Wine is used unmodified;
# the whole Alpha world lives above this one binary.
$(BUILD)/winhost.exe: $(BUILD)/winhost.w64.o $(BUILD)/jit.w64.o $(BUILD)/helpers.w64.o
	$(MINGW) -O2 -g -o $@ $^ $(WINLIBS)

guest:
	@sh win32/build-guest.sh

run: all
	@sh run.sh

test: $(BUILD)/axpemu
	cd tests && python3 difftest.py --classes int,int1,mem,branch,fp,fp1,fpr,mvi,fmem,fmov

clean:
	rm -rf $(BUILD)
