#include "../includes.h"

/**
 * contentinfo: get content info from http response
 * TODO: error handling
 * @param res pointer to http response in string format
 * @param result pointer to string array to store the parsed result
 * @return void
*/
void contentinfo(char* res, char** result) {
    char* content_length_header = "Content-Length";
    char* content_type_header = "Content-Type";

    char* parsed_length = NULL;
    char* parsed_type = NULL;

    char *token = NULL;
    token = strtok(res, "\n");

    int tlength;
    while (token) {
        for (int i = 0; i < strlen(content_length_header); i++) {
            if (token[i] != content_length_header[i]) {
                break;
            } else if (i == strlen(content_length_header) - 1) {
                tlength = strlen(token);
                parsed_length = malloc(tlength);
                
                strcpy(parsed_length, token);
                result[0] = parsed_length;
            }
        }

        for (int i = 0; i < strlen(content_type_header); i++) {
            if (token[i] != content_type_header[i]) {
                break;
            } else if (i == strlen(content_type_header) - 1) {
                tlength = strlen(token);
                parsed_type = malloc(tlength);
                
                strcpy(parsed_type, token);
                result[1] = parsed_type;
            }
        }

        token = strtok(NULL, "\n");
    }
}

/**
 * parse_hcontentlength: get content length as int from content length header
 * TODO: error handling
 * @param hcontent pointer to content length header
 * @return content length as int
*/
int parse_hcontentlength(char* hcontent) {
    int content_length;

    hcontent = strtok(hcontent, " ");
    hcontent = strtok(NULL, " ");
    content_length = strtol(hcontent, NULL, 10);

    return content_length;
}

/**
 * parse_hcontenttype: get content type as string from content type header
 * @param hcontent pointer to content type header
 * @return content type as string
*/
char* parse_hcontenttype(char* hcontent) {
    char* content_type;

    hcontent = strtok(hcontent, " ");
    hcontent = strtok(NULL, " ");
    content_type = hcontent;

    return content_type;
}