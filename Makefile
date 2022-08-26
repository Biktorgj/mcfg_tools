all: clean mcfg_tools

mcfg_tools:
	@$(CC) $(CFLAGS) -Wall sha256.c convert_mcfg.c -o convert_mcfg
	@$(CC) $(CFLAGS) -Wall sha256.c extract_mcfg.c -o extract_mcfg
	@chmod +x extract_mcfg convert_mcfg

clean:
	@rm -rf extract_mcfg convert_mcfg
