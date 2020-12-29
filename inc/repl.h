/*
+----------------------------------------+
|              REPL module               |
|                                        |
|   this is the command line interface   |
|            of netmon                   |
|                                        |
|  Author: f0lg0                         |
|  Date: 27-12-2020 (dd-mm-yyyy)         |
+----------------------------------------+
*/

#include "includes.h"

/* [BEGIN] Input Buffer Logic [BEGIN] */

/**
 * input_buffer: buffer to handle user input
*/
typedef struct {
    char* buffer;
    size_t buffer_length;
    ssize_t input_length;
} input_buffer;

/**
 * new_input_buffer: creates a new input buffer by allocating the necessary memory
 * @param void
 * @return a pointer to the newly created buffer
*/
input_buffer* new_input_buffer() {
    input_buffer* ibuff = (input_buffer *)malloc(sizeof(input_buffer));
    ibuff->buffer = NULL;
    ibuff->buffer_length = 0;
    ibuff->input_length = 0;

    return ibuff;
}

/**
 * print_prompt: prints the prompt line
 * @param void
 * @return void
*/
void print_prompt() { printf("[ \033[1;37mnetmon\033[0m ]$ "); }

/**
 * print_help: prints the help screen
 * @param void
 * @return void
*/
void print_help() {
    printf("\nCOMMAND\t\tUSAGE\n");
    printf("\nwhois\t\twhois [TARGET] --> e.g. 'google.com'. DO NOT SPECIFY THE PROTOCOL (http, https, etc.)\n\n");
}

/**
 * read_input: wrapper around getline that reads the input and saves it to the given buffer
 * @param ibuff an input buffer
 * @return void
*/
void read_input(input_buffer* ibuff) {
    ssize_t rbytes = getline(&(ibuff->buffer), &(ibuff->buffer_length), stdin);

    if (rbytes <= 0) {
        printf("[ \033[1;31mERROR\033[0m ] Error reading input.\n");
        exit(EXIT_FAILURE);
    }

    // Ignore trailing newline
    ibuff->input_length = rbytes - 1;
    ibuff->buffer[rbytes - 1] = 0;
}

/**
 * close_input_buffer:frees the memory allocated for an input buffer and the buffer element of the respective structure (getline allocates memory for ibuff->buffer)
 * @param ibuff an input buffer
 * @return void
*/
void close_input_buffer(input_buffer* ibuff) {
    free(ibuff->buffer);
    free(ibuff);
}

/* [END] Input Buffer Logic [END] */

/**
 * meta_command_result: status codes for meta command execution
*/
typedef enum {
    META_COMMAND_SUCCESS,
    META_COMMAND_UNRECOGNIZED_COMMAND
} meta_command_result;

/**
 * command_type: type of a command
*/
typedef enum { COMMAND_INFO, COMMAND_SNIFFER } command_type;

/**
 * command_payload: the payload of a command like sniff or whois
*/
typedef struct {
    char target[256];
    char interface[12];
    int pckt_num;
    char logfile[256];
} command_payload;

/**
 * command: a command from the cli
*/
typedef struct {
    command_type type;
    command_payload payload;
} command;

/**
 * prepare_result: status codes while preparing the execution of a command
*/
typedef enum { PREPARE_SUCCESS, PREPARE_UNRECOGNIZED_COMMAND, PREPARE_SYNTAX_ERROR } prepare_result;

/**
 * execute_result: status codes for executable commands 
*/
typedef enum { EXECUTE_SUCCESS, EXECUTE_FAILURE } execute_result;

/**
 * parse_meta_command: parse a given meta command
 * @param ibuff a pointer to an instance of an input buffer
 * @return META_COMMAND status code
*/
meta_command_result parse_meta_command(input_buffer* ibuff) {
    if (strcmp(ibuff->buffer, ".exit") == 0) {
        close_input_buffer(ibuff);
        exit(EXIT_SUCCESS);
    } else if (strcmp(ibuff->buffer, ".help") == 0) {
        print_help();
        return META_COMMAND_SUCCESS;
    } else {
        return META_COMMAND_UNRECOGNIZED_COMMAND;
    }
}

/**
 * prepare_command: prepare a given command for execution
 * @param ibuff a pointer to an instance of an input buffer
 * @param command a pointer to a command 
 * @return PREPARE status code
*/
prepare_result prepare_command(input_buffer* ibuff, command* cmd) {
    if (strncmp(ibuff->buffer, "whois", 5) == 0) {
        cmd->type = COMMAND_INFO;

        int args = sscanf(ibuff->buffer, "whois %255s", cmd->payload.target);
        if (args < 1) {
            return PREPARE_SYNTAX_ERROR;
        }
        return PREPARE_SUCCESS;
    }

    if (strncmp(ibuff->buffer, "sniff", 5) == 0) {
        cmd->type = COMMAND_SNIFFER;
        
        int args = sscanf(ibuff->buffer, "sniff %d", &(cmd->payload.pckt_num));
        if (args < 1) {
            return PREPARE_SYNTAX_ERROR;
        }

        return PREPARE_SUCCESS;
    }

    return PREPARE_UNRECOGNIZED_COMMAND;
}

/**
 * execute_whois: executes the command 'whois'
 * @param cmd instance of the 'command' structure
 * @return EXECUTE status code
*/
execute_result execute_whois(command* cmd) {
    hostinfo* hinfo = showip(cmd->payload.target);

    if (hinfo) {
        printf("IP addresses for %s:\n\n", cmd->payload.target);
        printf("\tIPv4: %s\n", hinfo->ipstr_v4);
        printf("\tIPv6: %s\n", hinfo->ipstr_v6);

        free(hinfo->hostname);
        free(hinfo);
    } else {
        return EXECUTE_FAILURE;
    }

    return EXECUTE_SUCCESS;
}

/**
 * execute_sniff. executes the command 'sniff' that triggers the packet sniffer
 * @param void (in the future we will have to pass the command)
 * @return EXECUTE status code
*/
execute_result execute_sniff(command* cmd) {
    int rsock = open_rsock();
    if (rsock == -1) return EXECUTE_FAILURE;

    // allocating buffer to receive data
    unsigned char* buffer = alloc_pckts_buffer();
    
    int status = run_sniffer(&rsock, buffer, cmd->payload.pckt_num);
    if (status != 0) return EXECUTE_FAILURE;

    return EXECUTE_SUCCESS;
}


/**
 * execute_command: wrapper around the possible command operations (whois, sniff, etc)
 * @param command a pointer to a command structure
 * @return EXECUTE status code
*/
execute_result execute_command(command* cmd) {
    switch (cmd->type) {
        case (COMMAND_SNIFFER):
            return execute_sniff(cmd);
        case (COMMAND_INFO):
            return execute_whois(cmd);
        default:
            printf("[ \033[1;31mERROR\033[0m ] Unrecognized command.\n");
            break;
    }
}