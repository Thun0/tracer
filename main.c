//#define REGISTER_IP EIP
//#define TRAP_LEN    1
//#define TRAP_INST   0xCC
//#define TRAP_MASK   0xFFFFFF00
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>

#define REGISTER_IP RIP
#define TRAP_LEN    1
#define TRAP_INST   0xCC
#define TRAP_MASK   0xFFFFFFFFFFFFFF00

#define FILEPATH_LEN 100
#define SYMBOL_NAME_LEN 30

char filename[FILEPATH_LEN+1];
FILE* fp;
int child_pid;

typedef struct 
{
	long addr;
	long original_code;
	char name[SYMBOL_NAME_LEN+1];
} Tracepoint;

Tracepoint* tracepoints;
int tp_count;

void parse_elf_file()
{
	Elf64_Ehdr elf_header;
	Elf64_Shdr section_header;
	fp = fopen(filename, "r");
	if(!fp)
	{
		printf("Failed to open ELF file!\n");
		exit(-1);
	}
	
	fread(&elf_header, 1, sizeof(elf_header), fp);

	fseek(fp, elf_header.e_shoff, SEEK_SET);

	for(int i = 0; i < elf_header.e_shnum; ++i)
	{
		fread(&section_header, 1, sizeof(section_header), fp);
		if(section_header.sh_type == SHT_SYMTAB)
		{
			Elf64_Shdr strtab_header;
			long strtab_offset = elf_header.e_shoff+section_header.sh_link*sizeof(section_header);
			fseek(fp, strtab_offset, SEEK_SET);
			fread(&strtab_header, 1, sizeof(strtab_header), fp);

			fseek(fp, section_header.sh_offset, SEEK_SET);
			int entries = section_header.sh_size / section_header.sh_entsize;
			//printf("Found symtab with %d entries\n", entries);
			tracepoints = malloc(entries*sizeof(Tracepoint));//won't be bigger
			for(i = 0; i < entries; ++i)
			{
				Elf64_Sym symbol;
				fread(&symbol, 1, sizeof(symbol), fp);
				if(ELF64_ST_TYPE(symbol.st_info) == STT_FUNC)
				{
					//printf("Found function at offset %lx", symbol.st_value);
					if(symbol.st_name != 0)
					{
						long pos = ftell(fp);
						fseek(fp, strtab_header.sh_offset+symbol.st_name, SEEK_SET);
						//char symbol_name[SYMBOL_NAME_LEN+1];
						//fread(symbol_name, SYMBOL_NAME_LEN, sizeof(char), fp);
						//printf(" %s", symbol_name);

						tracepoints[tp_count].addr = symbol.st_value;
						fread(tracepoints[tp_count].name, SYMBOL_NAME_LEN, sizeof(char), fp);

						fseek(fp, pos, SEEK_SET);
						tp_count++;
					}
					//printf("\n");
				}
			}
			return;
		}
	}
}


void prepare_tracepoints()
{
	parse_elf_file();
	for(int i = 0; i < tp_count; ++i)
	{
		tracepoints[i].original_code = ptrace(PTRACE_PEEKTEXT, child_pid, tracepoints[i].addr, 0);
		printf("%s: %lx\n", tracepoints[i].name, tracepoints[i].original_code);
	}
}

void trace()
{

}

int main(int argc, char** argv)
{
	if(argc < 2)
	{
		printf("Usage: tracer path\n");
		return -1;
	}
	strncpy(filename, argv[1], FILEPATH_LEN);
	child_pid = fork();
	if(child_pid == 0)
	{
		//child process
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execl(argv[1], argv[1], NULL);
		printf("Failed to execl!!\n");
		exit(-1);
	}
	else
	{
		//parent - tracer
		printf("PID %d\n", child_pid);
		//sleep(2);
		prepare_tracepoints();
		trace();
		free(tracepoints);
	}
	return 0;
}