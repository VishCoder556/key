#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int writeContentToFile(const char *filename, const char *content) {
    FILE *f = fopen(filename, "w");
    fwrite(content, sizeof(char), strlen(content), f);
    fclose(f);
    return 1;
}



int main() {
    const char *filename = "example.txt";
    const char *new_content = "Modified Content\n";
    struct stat st;
    mode_t orig_mode;


    char *original_content;
    size_t original_size;

    int statn = stat(filename, &st);

    if (statn != -1)  {
        original_content = malloc(st.st_size + 1);
        if (original_content == NULL) {
            perror("Error allocating memory");
            return 1;
        }

        int fd = open(filename, O_RDONLY);
        if (fd == -1) {
            perror("Error opening file for reading");
            free(original_content);
            return 1;
        }

        ssize_t bytes_read = read(fd, original_content, st.st_size);
        if (bytes_read == -1) {
            perror("Error reading file");
            free(original_content);
            close(fd);
            return 1;
        }
        original_content[st.st_size] = '\0';
        close(fd);
        orig_mode = st.st_mode;
    }

    if (!writeContentToFile(filename, new_content)) {
        printf("Failed to write modified content to file.\n");
        free(original_content);
        return 1;
    }

    if (statn == -1){

        if (unlink(filename) == -1) {
            perror("Error deleting file");
            return 0;
        }
    }else {
        if (!writeContentToFile(filename, original_content)) {
            printf("Failed to revert to original content.\n");
            free(original_content);
            return 1;
        }
        if (chmod(filename, orig_mode) == -1) {
            perror("Error reverting file permissions");
            printf("Failed to revert file permissions.\n");
            free(original_content);
            return 0;
        }
        free(original_content);
    }

    printf("Changes reverted successfully.\n");

    return 0;
}
