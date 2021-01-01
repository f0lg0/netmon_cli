#ifndef REPL_H
#define REPL_H

/* [BEGIN] Input Buffer Logic [BEGIN] */

/**
 * input_buffer: buffer to handle user input
*/
typedef struct {
    char* buffer;
    size_t buffer_length;
    ssize_t input_length;
} input_buffer;

input_buffer* new_input_buffer();
void print_prompt();
void print_help();
void read_input(input_buffer* ibuff);
void close_input_buffer(input_buffer* ibuff);

/* [END] Input Buffer Logic [END] */

/* [BEGIN] Commands Logic [BEGIN] */

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
 * command_payload: the payload of a command like sniff or showip
*/
typedef struct {
    char target[256];
    int pckt_num;
    int logfile;
} command_payload ;

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

meta_command_result parse_meta_command(input_buffer* ibuff);
prepare_result prepare_command(input_buffer* ibuff, command* cmd);
execute_result execute_showip(command* cmd);
execute_result execute_sniff(command* cmd);
execute_result execute_command(command* cmd);

/* [END] Commands Logic [END] */


#endif