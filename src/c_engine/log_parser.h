#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE_LENGTH 4096
#define MAX_PAYLOAD_LENGTH 2048
#define MAX_ATTACK_TYPE_LENGTH 64
#define MAX_TIMESTAMP_LENGTH 32
#define MAX_IP_LENGTH 64
#define MAX_SESSION_LENGTH 128

typedef enum {
    ATTACK_SQL_INJECTION,
    ATTACK_XSS,
    ATTACK_COMMAND_INJECTION,
    ATTACK_FILE_INCLUSION,
    ATTACK_BRUTE_FORCE,
    ATTACK_CSRF,
    ATTACK_UNKNOWN
} AttackType;

typedef struct {
    char timestamp[MAX_TIMESTAMP_LENGTH];
    AttackType attack_type;
    char attack_type_str[MAX_ATTACK_TYPE_LENGTH];
    int success;
    char payload[MAX_PAYLOAD_LENGTH];
    char source_ip[MAX_IP_LENGTH];
    char session_id[MAX_SESSION_LENGTH];
    int severity;
} LogEntry;

typedef struct {
    LogEntry *entries;
    int count;
    int capacity;
} LogCollection;

// Function prototypes
LogCollection* init_log_collection(void);
void free_log_collection(LogCollection *collection);
int parse_log_line(const char *line, LogEntry *entry);
int add_log_entry(LogCollection *collection, LogEntry *entry);
int write_json_output(LogCollection *collection, const char *output_file);
AttackType parse_attack_type(const char *type_str);
const char* attack_type_to_string(AttackType type);
int calculate_severity(LogEntry *entry);

#endif
