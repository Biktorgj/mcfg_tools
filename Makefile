all: clean mcfg_tools

mcfg_tools:
	@$(CC) $(CFLAGS) -Wall sha256.c unpack_mcfg.c -o unpack_mcfg
	@$(CC) $(CFLAGS) -Wall sha256.c pack_mcfg.c -o pack_mcfg
	@chmod +x unpack_mcfg convert_mcfg pack_mcfg

clean:
	@rm -rf unpack_mcfg pack_mcfg
