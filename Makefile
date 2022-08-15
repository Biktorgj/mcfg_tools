all: clean make_mibib

make_mibib:
	@$(CC) $(CFLAGS) -Wall read_mcfg.c -o read_mcfg
	@$(CC) $(CFLAGS) -Wall write_mcfg.c -o write_mcfg
	@chmod +x read_mcfg write_mcfg

clean:
	@rm -rf read_mcfg write_mcfg
