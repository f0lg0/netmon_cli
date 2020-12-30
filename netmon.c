#include "inc/includes.h"
#include "inc/info_gathering.h"
#include "inc/sniffer.h"
#include "inc/repl.h"

FILE* log_f = NULL;

int main(int argc, char *argv[]) {
    input_buffer* ibuff = new_input_buffer();

    while (1) {
        print_prompt();
        read_input(ibuff);

        if (ibuff->buffer[0] == '.') {
            switch (parse_meta_command(ibuff)) {
                case (META_COMMAND_SUCCESS):
                    continue;
                case (META_COMMAND_UNRECOGNIZED_COMMAND):
                    printf("Unrecognized command '%s'\n", ibuff->buffer);
                    continue;
            }
        }

        command cmd;
        switch (prepare_command(ibuff, &cmd)) {
            case (PREPARE_SUCCESS):
                break;
            
            case (PREPARE_SYNTAX_ERROR):
                printf("Syntax error. Could not parse command.\n");
                continue;

            case (PREPARE_UNRECOGNIZED_COMMAND):
                printf("Unrecognized keyword at start of '%s'.\n", ibuff->buffer);
                continue;
        }

        switch (execute_command(&cmd)) {
            case (EXECUTE_SUCCESS):
                printf("[\033[1;32mSUCCESS\033[0m] Executed. \n");
                break;

            case (EXECUTE_FAILURE):
                printf("[\033[1;31mFAILURE\033[0m] failed to execute. \n");
                break;
            }
    }

    return 0;
}
