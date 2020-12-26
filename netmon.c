#include "inc/includes.h"
#include "inc/info_gathering.h"
#include "inc/sniffer.h"
#include "inc/repl.h"

int main(int argc, char *argv[]) {
    // hostinfo* hinfo = showip("google.com");
    // printf("IP addresses for %s:\n\n", "google.com");
    // printf("\tIPv4: %s\n", hinfo->ipstr_v4);
    // printf("\tIPv6: %s\n", hinfo->ipstr_v6);

    // free(hinfo->hostname);
    // free(hinfo);

    // FILE* logfile;
    // if (openlog(logfile) != 0) {
    //     printf("[ERROR] Unable to open log file.\n");
    //     return 1;
    // }

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
                printf("[SUCCESS] Executed. \n");
                break;

            case (EXECUTE_FAILURE):
                printf("[FAILUR] failed to execute. \n");
                break;
            }
    }

    return 0;
}
