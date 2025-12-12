#include "log_parser.h"
#include <ctype.h>

LogCollection* init_log_collection(void) {
    LogCollection *collection = (LogCollection*)malloc(sizeof(LogCollection));
    if (!collection) return NULL;

    collection->capacity = 1000;
    collection->count = 0;
    collection->entries = (LogEntry*)malloc(sizeof(LogEntry) * collection->capacity);

    if (!collection->entries) {
        free(collection);
        return NULL;
    }

    return collection;
}

void free_log_collection(LogCollection *collection) {
    if (collection) {
        if (collection->entries) {
            free(collection->entries);
        }
        free(collection);
    }
}

AttackType parse_attack_type(const char *type_str) {
    if (strstr(type_str, "SQL_INJECTION") || strstr(type_str, "SQL INJECTION")) {
        return ATTACK_SQL_INJECTION;
    } else if (strstr(type_str, "XSS") || strstr(type_str, "CROSS_SITE_SCRIPTING")) {
        return ATTACK_XSS;
    } else if (strstr(type_str, "COMMAND_INJECTION") || strstr(type_str, "CMD_INJECTION")) {
        return ATTACK_COMMAND_INJECTION;
    } else if (strstr(type_str, "FILE_INCLUSION") || strstr(type_str, "LFI") || strstr(type_str, "RFI")) {
        return ATTACK_FILE_INCLUSION;
    } else if (strstr(type_str, "BRUTE_FORCE") || strstr(type_str, "BRUTE FORCE")) {
        return ATTACK_BRUTE_FORCE;
    } else if (strstr(type_str, "CSRF")) {
        return ATTACK_CSRF;
    }
    return ATTACK_UNKNOWN;
}

const char* attack_type_to_string(AttackType type) {
    switch(type) {
        case ATTACK_SQL_INJECTION: return "SQL_INJECTION";
        case ATTACK_XSS: return "XSS";
        case ATTACK_COMMAND_INJECTION: return "COMMAND_INJECTION";
        case ATTACK_FILE_INCLUSION: return "FILE_INCLUSION";
        case ATTACK_BRUTE_FORCE: return "BRUTE_FORCE";
        case ATTACK_CSRF: return "CSRF";
        default: return "UNKNOWN";
    }
}

int calculate_severity(LogEntry *entry) {
    int severity = 1;

    if (entry->success) {
        severity += 3;
    }

    switch(entry->attack_type) {
        case ATTACK_SQL_INJECTION:
        case ATTACK_COMMAND_INJECTION:
            severity += 4;
            break;
        case ATTACK_FILE_INCLUSION:
        case ATTACK_XSS:
            severity += 3;
            break;
        case ATTACK_CSRF:
            severity += 2;
            break;
        case ATTACK_BRUTE_FORCE:
            severity += 2;
            break;
        default:
            severity += 1;
    }

    if (severity > 10) severity = 10;
    return severity;
}

// Parse log format: 2025-12-12 10:39:15 | SQL_INJECTION | SUCCESS | ' AND SLEEP(3) | 192.168.1.100 | SESSION_ABC123
int parse_log_line(const char *line, LogEntry *entry) {
    char temp_line[MAX_LINE_LENGTH];
    strncpy(temp_line, line, MAX_LINE_LENGTH - 1);
    temp_line[MAX_LINE_LENGTH - 1] = '\0';

    // Remove newline
    char *newline = strchr(temp_line, '\n');
    if (newline) *newline = '\0';

    // Parse timestamp
    char *token = strtok(temp_line, "|");
    if (!token) return 0;

    // Trim whitespace
    while (*token == ' ') token++;
    char *end = token + strlen(token) - 1;
    while (end > token && *end == ' ') end--;
    *(end + 1) = '\0';

    strncpy(entry->timestamp, token, MAX_TIMESTAMP_LENGTH - 1);
    entry->timestamp[MAX_TIMESTAMP_LENGTH - 1] = '\0';

    // Parse attack type
    token = strtok(NULL, "|");
    if (!token) return 0;
    while (*token == ' ') token++;
    end = token + strlen(token) - 1;
    while (end > token && *end == ' ') end--;
    *(end + 1) = '\0';

    strncpy(entry->attack_type_str, token, MAX_ATTACK_TYPE_LENGTH - 1);
    entry->attack_type_str[MAX_ATTACK_TYPE_LENGTH - 1] = '\0';
    entry->attack_type = parse_attack_type(token);

    // Parse success/failure
    token = strtok(NULL, "|");
    if (!token) return 0;
    while (*token == ' ') token++;
    end = token + strlen(token) - 1;
    while (end > token && *end == ' ') end--;
    *(end + 1) = '\0';

    entry->success = (strstr(token, "SUCCESS") != NULL) ? 1 : 0;

    // Parse payload
    token = strtok(NULL, "|");
    if (!token) return 0;
    while (*token == ' ') token++;
    end = token + strlen(token) - 1;
    while (end > token && *end == ' ') end--;
    *(end + 1) = '\0';

    strncpy(entry->payload, token, MAX_PAYLOAD_LENGTH - 1);
    entry->payload[MAX_PAYLOAD_LENGTH - 1] = '\0';

    // Parse source IP (optional)
    token = strtok(NULL, "|");
    if (token) {
        while (*token == ' ') token++;
        end = token + strlen(token) - 1;
        while (end > token && *end == ' ') end--;
        *(end + 1) = '\0';
        strncpy(entry->source_ip, token, MAX_IP_LENGTH - 1);
        entry->source_ip[MAX_IP_LENGTH - 1] = '\0';
    } else {
        strcpy(entry->source_ip, "UNKNOWN");
    }

    // Parse session ID (optional)
    token = strtok(NULL, "|");
    if (token) {
        while (*token == ' ') token++;
        end = token + strlen(token) - 1;
        while (end > token && *end == ' ') end--;
        *(end + 1) = '\0';
        strncpy(entry->session_id, token, MAX_SESSION_LENGTH - 1);
        entry->session_id[MAX_SESSION_LENGTH - 1] = '\0';
    } else {
        strcpy(entry->session_id, "NONE");
    }

    entry->severity = calculate_severity(entry);

    return 1;
}

int add_log_entry(LogCollection *collection, LogEntry *entry) {
    if (collection->count >= collection->capacity) {
        collection->capacity *= 2;
        LogEntry *new_entries = (LogEntry*)realloc(collection->entries,
                                                   sizeof(LogEntry) * collection->capacity);
        if (!new_entries) return 0;
        collection->entries = new_entries;
    }

    collection->entries[collection->count++] = *entry;
    return 1;
}

// Escape JSON string
void escape_json_string(const char *input, char *output, int max_len) {
    int j = 0;
    for (int i = 0; input[i] && j < max_len - 2; i++) {
        if (input[i] == '"' || input[i] == '\\') {
            output[j++] = '\\';
        }
        output[j++] = input[i];
    }
    output[j] = '\0';
}

int write_json_output(LogCollection *collection, const char *output_file) {
    FILE *fp = fopen(output_file, "w");
    if (!fp) return 0;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"total_events\": %d,\n", collection->count);
    fprintf(fp, "  \"events\": [\n");

    for (int i = 0; i < collection->count; i++) {
        LogEntry *entry = &collection->entries[i];
        char escaped_payload[MAX_PAYLOAD_LENGTH * 2];
        escape_json_string(entry->payload, escaped_payload, sizeof(escaped_payload));

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"timestamp\": \"%s\",\n", entry->timestamp);
        fprintf(fp, "      \"attack_type\": \"%s\",\n", attack_type_to_string(entry->attack_type));
        fprintf(fp, "      \"success\": %s,\n", entry->success ? "true" : "false");
        fprintf(fp, "      \"payload\": \"%s\",\n", escaped_payload);
        fprintf(fp, "      \"source_ip\": \"%s\",\n", entry->source_ip);
        fprintf(fp, "      \"session_id\": \"%s\",\n", entry->session_id);
        fprintf(fp, "      \"severity\": %d\n", entry->severity);
        fprintf(fp, "    }%s\n", (i < collection->count - 1) ? "," : "");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return 1;
}
