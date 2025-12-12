#include "log_parser.h"

void print_usage(const char *program_name) {
    printf("Usage: %s <input_log_file> <output_json_file>\n", program_name);
    printf("Example: %s data/raw_logs/attack.log data/parsed_logs/attack.json\n", program_name);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];

    FILE *fp = fopen(input_file, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return 1;
    }

    LogCollection *collection = init_log_collection();
    if (!collection) {
        fprintf(stderr, "Error: Failed to initialize log collection\n");
        fclose(fp);
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    int line_number = 0;
    int parsed_count = 0;
    int error_count = 0;

    printf("Parsing log file: %s\n", input_file);

    while (fgets(line, sizeof(line), fp)) {
        line_number++;

        // Skip empty lines and comments
        if (line[0] == '\n' || line[0] == '#') continue;

        LogEntry entry;
        memset(&entry, 0, sizeof(LogEntry));

        if (parse_log_line(line, &entry)) {
            if (add_log_entry(collection, &entry)) {
                parsed_count++;
                printf("  [%d] Parsed: %s | %s | %s\n",
                       line_number,
                       entry.timestamp,
                       attack_type_to_string(entry.attack_type),
                       entry.success ? "SUCCESS" : "FAILURE");
            } else {
                fprintf(stderr, "  [%d] Error: Failed to add log entry\n", line_number);
                error_count++;
            }
        } else {
            fprintf(stderr, "  [%d] Warning: Failed to parse line\n", line_number);
            error_count++;
        }
    }

    fclose(fp);

    printf("\n");
    printf("Parsing complete:\n");
    printf("  Total lines: %d\n", line_number);
    printf("  Successfully parsed: %d\n", parsed_count);
    printf("  Errors: %d\n", error_count);

    printf("\nWriting JSON output to: %s\n", output_file);

    if (write_json_output(collection, output_file)) {
        printf("Successfully wrote %d events to JSON file\n", collection->count);
    } else {
        fprintf(stderr, "Error: Failed to write JSON output\n");
        free_log_collection(collection);
        return 1;
    }

    free_log_collection(collection);
    printf("\nLog parsing engine completed successfully.\n");

    return 0;
}
