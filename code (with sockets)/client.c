#include "communication.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>     //for ip address handling
#include <netdb.h>

#define TEXT_LIMIT 512
#define MAX_ACCOUNTS 10

struct Account
{
char username[TEXT_LIMIT];
char password[TEXT_LIMIT];
};

struct Account accounts[MAX_ACCOUNTS];
int num_accounts=0;

// Load accounts from file
void load_accounts()
{
    FILE *file = fopen("accounts.txt", "r");
    if (file == NULL) return;
    while (fscanf(file, "%s %s", accounts[num_accounts].username, accounts[num_accounts].password) == 2)
    {
        num_accounts++;
        if (num_accounts >= MAX_ACCOUNTS) break;
    }
    fclose(file);
}

// Save a new account to file
void save_account(const char *username, const char *password)
{
    FILE *file = fopen("accounts.txt", "a");
    if (file != NULL)
    {
        fprintf(file, "%s %s\n", username, password);
        fclose(file);
    }
}

int login(char *username, char *password)
{
    for (int i=0;i<num_accounts;i++)
    {
        if (strcmp(accounts[i].username, username) == 0 &&
            strcmp(accounts[i].password, password) == 0)
            {
            return 1;
        }
    }
    return 0;
}


int create_account(char *username, char *password)
{
    if (num_accounts >= MAX_ACCOUNTS)
    {
        printf("Account limit reached. Cannot create a new account.\n");
        return 0;
    }

    // Check if the username already exists
    for (int i = 0; i < num_accounts; i++)
    {
        if (strcmp(accounts[i].username, username) == 0)
        {
            printf("Username already exists.\n");
            return 0;
        }
    }
    strcpy(accounts[num_accounts].username, username);
    strcpy(accounts[num_accounts].password, password);
    save_account(username, password);
    num_accounts++;
    return 1;
}


int main()
{
    int sock=0;
    struct sockaddr_in serv_addr;
    if ((sock=socket(AF_INET,SOCK_STREAM,0)) < 0)
    {
        printf("\n Socket Creation Error \n");
        return -1;
    }
   
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_port=htons(PORT);
   
    char server_ip[16];
    printf("\nEnter Server IP Address to Connect: ");
    scanf("%15s",server_ip);
    getchar();
   
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
   
    if (connect(sock,(struct sockaddr *)&serv_addr,sizeof(serv_addr))<0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    int pid=getpid();
    printf("[CLIENT %d] Connected to Server at %s:%d\n",pid,server_ip,PORT);
    printf("\n------------WELCOME [CLIENT %d]---------------\n",pid);
   
    load_accounts();
    char jobtext[TEXT_LIMIT];
    struct message msg;
    msg.mestype=1;
    int choice;
   
    char username[TEXT_LIMIT],password[TEXT_LIMIT];
    int logged_in = 0;
   
     while (!logged_in)
     {
        printf("\n1. Login\n");
        printf("2. Create Account\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();
       
        if (choice == 1)
        {
            printf("\nEnter Username: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = '\0';

            printf("Enter Password: ");
            fgets(password, sizeof(password), stdin);
            password[strcspn(password, "\n")] = '\0';

            if (login(username, password))
            {
                printf("Login successful.\n");
                logged_in = 1;
            }
            else
            {
                printf("Invalid username or password. Please try again.\n");
            }
        }
        else if (choice == 2)
        {
            printf("\nEnter a new Username: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = '\0';

            printf("Enter a new Password: ");
            fgets(password, sizeof(password), stdin);
            password[strcspn(password, "\n")] = '\0';

            if (create_account(username, password))
            {
                printf("Account created successfully\n");
            }
            else
            {
                printf("Account creation failed.\n");
            }
        }
        else
        {
            printf("Invalid option. Please try again.\n");
        }
    }
   
    while (1)
    {
        printf("\nDo you want to:\n");
        printf("1. Add a Printing Job\n");
        printf("2. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();
       
        if (choice==2)
        {
            printf("Exiting...\n");
            break;
        }
        else if (choice==1)
        {
             int job_type;
             printf("\n-----------Choose Job Type--------------\n\n");
             printf("1. Submit Existing File (server will read the file)\n");
             printf("2. Create a New file (you provide heading and content)\n");
             printf("Enter your choice: ");
             scanf("%d", &job_type);
             getchar();
             
             if (job_type == 1) {
            printf("\n------------------------------------------------------------\n");
            char filename[TEXT_LIMIT];
            printf("[CLIENT %d] filename: ", pid);
            fgets(filename, sizeof(filename), stdin);
            filename[strcspn(filename, "\n")] = '\0';
           
            if (strcmp(filename, "exit") == 0) {
                break;
            }
           
            strncpy(msg.mesfilename, filename, TEXT_LIMIT);
            msg.job_type = 1;
           
    // Read file content
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        printf("[CLIENT %d] Could not open file: %s\n", pid, filename);
        continue;  // Skip to next iteration
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Read file content
    char *file_content = (char*)malloc(file_size + 1);
    size_t bytes_read = fread(file_content, 1, file_size, file);
    file_content[bytes_read] = '\0';
    fclose(file);

              int priority;
              printf("Enter Priority (1-5, 1=highest): ");
              scanf("%d", &priority);
              getchar();
           
            msg.priority=priority;
            strncpy(msg.mesfilename, filename, TEXT_LIMIT);
            strncpy(msg.mescontent,file_content, TEXT_LIMIT);
   
            send(sock, &msg, sizeof(msg), 0);
            printf("[CLIENT %d] Sent request to print existing file: %s\n", pid, filename);
             
            char buffer[MSG_SIZE] = {0};
            read(sock, buffer, MSG_SIZE);
            printf("[CLIENT %d] Server Response: %s\n", pid, buffer);
        }
           
            else if (job_type==2)
            {
                printf("\n------------------------------------------------------------\n");
                printf("Enter 'exit' if you want to discontinue");
                printf("\n------------------------------------------------------------\n\n");      
                char filename[TEXT_LIMIT], heading[TEXT_LIMIT], content[TEXT_LIMIT];
                int priority;
               
                printf("[CLIENT %d] Filename: ", pid);
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = '\0';
               
                if (strcmp(filename, "exit") == 0)
                    break;
                   
                 printf("Enter Priority (1-5, 1=highest): ");
                 scanf("%d", &priority);
                 getchar();
               
                printf("\n---------Now Enter Content of File---------\n");
                printf("\nHeading: ");
                fgets(heading, sizeof(heading), stdin);
                heading[strcspn(heading, "\n")] = '\0';
                if (strcmp(heading, "exit") == 0)
                    break;

                printf("Content: ");
                fgets(content, sizeof(content), stdin);
                content[strcspn(content, "\n")] = '\0';
                if (strcmp(content, "exit") == 0)
                    break;

                msg.job_type = 2;  // Explicitly set job type to 2
                strncpy(msg.mesfilename, filename, TEXT_LIMIT);
                strncpy(msg.mesheading, heading, TEXT_LIMIT);
                strncpy(msg.mescontent, content, TEXT_LIMIT);
                msg.priority=priority;
                send(sock, &msg, sizeof(msg), 0);
                printf("[CLIENT %d] Sent File: %s | Heading: %s | Content: %s\n", pid, msg.mesfilename,msg.mesheading,msg.mescontent);

                char buffer[MSG_SIZE] = {0};
                read(sock, buffer, MSG_SIZE);
                printf("[CLIENT %d] Server Response: %s\n", pid, buffer);
            }
        }
        else
        {
            printf("Invalid option. Please try again.\n");
        }
    }  
    close(sock);
    //free_pages(getpid());
    return 0;
}

-----------------------------------------------------------

server.c

-----------------------------------------------------------


#include "communication.h"
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

#define NUM_THREADS 4

JobQueue *queue = NULL;

// Virtual Memory Globals
JobMemory *job_memories[MAX_JOBS] = {NULL};
char phys_mem[NUM_FRAMES][PAGE_SIZE];
int used_frames = 0;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_not_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t queue_not_full = PTHREAD_COND_INITIALIZER;

void init_queue()
{
    queue = (JobQueue*)malloc(sizeof(JobQueue));
    queue->front = 0;
    queue->rear = 0;
    queue->count = 0;
    queue->current_algorithm = FCFS;         // default algorithm
    queue->rr_counter = 0;
}

void add_job_to_queue(Job new_job)
{
    pthread_mutex_lock(&queue_mutex);
    new_job.arrival_time = time(NULL);
    if (queue->count == MAX_JOBS)
    {
        pthread_cond_wait(&queue_not_full, &queue_mutex);
    }
   
    if (queue->current_algorithm == PRIORITY)
    {
        // Insert in priority order (lowest number first)
        int insert_pos = queue->rear;
        for (int i = 0; i < queue->count; i++)
        {
            int idx = (queue->front + i) % MAX_JOBS;
            if (queue->jobs[idx].priority > new_job.priority)
            {
                insert_pos = idx;
                break;
            }
        }
       
        for (int i = queue->rear; i != insert_pos; i = (i - 1 + MAX_JOBS) % MAX_JOBS)
        {
            int prev = (i - 1 + MAX_JOBS) % MAX_JOBS;
            queue->jobs[i] = queue->jobs[prev];
        }
       
        queue->jobs[insert_pos] = new_job;
        queue->rear = (queue->rear + 1) % MAX_JOBS;
    }
    else
    {
        // For FCFS and Round Robin, add to rear
        queue->jobs[queue->rear] = new_job;
        queue->rear = (queue->rear + 1) % MAX_JOBS;
    }
   
    queue->count++;
    pthread_cond_signal(&queue_not_empty);
    pthread_mutex_unlock(&queue_mutex);
   
    write_queue_to_log();
   
    printf("[SERVER] Added Job %d (Priority: %d, File: %s)\n",
           new_job.jobid, new_job.priority, new_job.filename);
}



int remove_job_from_queue(Job *job)
{
    pthread_mutex_lock(&queue_mutex);
    while (queue->count == 0)
    {
        pthread_cond_wait(&queue_not_empty, &queue_mutex);
    }

    // Default to FCFS if no algorithm is set
    if (queue->current_algorithm == FCFS || queue->current_algorithm == 0)
    {
        *job = queue->jobs[queue->front];
        queue->front = (queue->front + 1) % MAX_JOBS;
        queue->count--;
    }
   
    else if (queue->current_algorithm == PRIORITY)
    {
        // Find the job with highest priority (lowest number)
        int highest_prio_index = queue->front;
        for (int i = 1; i < queue->count; i++)
        {
            int current_index = (queue->front + i) % MAX_JOBS;
            if (queue->jobs[current_index].priority < queue->jobs[highest_prio_index].priority)
            {
                highest_prio_index = current_index;
            }
        }
       
        *job = queue->jobs[highest_prio_index];
       
        for (int i = highest_prio_index; i != queue->rear; i = (i + 1) % MAX_JOBS)
        {
            int next = (i + 1) % MAX_JOBS;
            if (next == queue->rear) break;
            queue->jobs[i] = queue->jobs[next];
        }
       
        queue->rear = (queue->rear - 1 + MAX_JOBS) % MAX_JOBS;
        queue->count--;
    }
   
    else if (queue->current_algorithm == ROUND_ROBIN)
    {
        *job = queue->jobs[queue->front];
        queue->front = (queue->front + 1) % MAX_JOBS;
        queue->count--;
    }

    pthread_cond_signal(&queue_not_full);
    pthread_mutex_unlock(&queue_mutex);
    return 1;
}

void view_log_file()
{
    printf("\n--- Current Queue Log ---\n");
    FILE* log_fp = fopen("queue_log.txt", "r");
   
    if (log_fp)
    {
        char line[256];
        while (fgets(line, sizeof(line), log_fp))
        {
            printf("%s", line);
        }
        fclose(log_fp);
    }
    else
    {
        perror("Error opening log file");
    }
    printf("------------------------\n");
}


void* worker_thread(void* arg)
{
    int thread_id = *(int*)arg;
    Job job;
    time_t start = time(NULL);
    while (1)
    {
        remove_job_from_queue(&job);

// ====== NEW: LOAD JOB PAGES INTO PHYSICAL MEMORY ======
        JobMemory *job_mem = job_memories[job.jobid % MAX_JOBS];
        if (!job_mem) {
            printf("[THREAD %d] ERROR: No memory allocated for Job %d!\n", thread_id, job.jobid);
            continue;
        }

       load_job_pages_into_memory(job, thread_id);

        printf("[THREAD %d] Processing Job ID = %d | Filename: %s \n\n",
         thread_id, job.jobid, job.filename);
       
        /*if (job.job_type == 1)  // Existing file read job
        {
            printf("[THREAD %d] Existing file requested\n", thread_id);
            printf("[THREAD %d] Content: %s\n", thread_id, job.content);
        }*/
       
         if (job.job_type == 1)  // Existing file content received from client
        {
         printf("[THREAD %d] Created a copy of client file: %s\n", thread_id, job.filename);
             printf("[THREAD %d] Content: %s\n", thread_id, job.content);
             FILE *fp = fopen(job.filename, "w");
            if (fp != NULL)
            {
                fprintf(fp, "\n%s\n", job.content);
                fclose(fp);
                printf("[THREAD %d] File %s created successfully.\n", thread_id, job.filename);
            }
            else
            {
                perror("Error creating file");
                printf("[THREAD %d] Error creating file %s.\n", thread_id, job.filename);
            }
           
           
        }
       
       
        else if (job.job_type == 2)
        {
            printf("[THREAD %d] Creating new file: %s\n", thread_id, job.filename);
            printf("[THREAD %d] Heading: %s\n", thread_id, job.heading);
            printf("[THREAD %d] Content: %s\n", thread_id, job.content);
           
            FILE *fp = fopen(job.filename, "w");
            if (fp != NULL)
            {
                fprintf(fp, "%s\n", job.heading);
                fprintf(fp, "\n%s\n", job.content);
                fclose(fp);
                printf("[THREAD %d] File %s created successfully.\n", thread_id, job.filename);
            }
            else
            {
                perror("Error creating file");
                printf("[THREAD %d] Error creating file %s.\n", thread_id, job.filename);
            }
        }  
       
        // Send acknowledgment back to client
        char ack_msg[MSG_SIZE];
        snprintf(ack_msg, MSG_SIZE, "Job %d Completed by Thread %d", job.jobid, thread_id);
        send(job.client_socket, ack_msg, strlen(ack_msg), 0);
       
        sleep(1); // Simulate processing time
        time_t end = time(NULL);
        job.completion_time = end;
        job.execution_time = (int)difftime(end, start);
       
        if (strcmp(job.content, "exit") == 0)
        {
            printf("[THREAD %d] Received exit signal. Exiting...\n", thread_id);
            break;
        }
    }
    return NULL;
}


void sort_queue_by_priority()
{
    if (queue->count <= 1) return;

    // Convert circular queue to linear array
    Job temp[MAX_JOBS];
    int temp_count = 0;
   
    // Copy jobs to temp array
    for (int i = 0; i < queue->count; i++)
    {
        int idx = (queue->front + i) % MAX_JOBS;
        temp[temp_count++] = queue->jobs[idx];
    }
   
    // Bubble sort by priority (lower number = higher priority)
    for (int i = 0; i < temp_count - 1; i++)
    {
        for (int j = 0; j < temp_count - i - 1; j++)
        {
            if (temp[j].priority > temp[j+1].priority)
            {
                Job swap = temp[j];
                temp[j] = temp[j+1];
                temp[j+1] = swap;
            }
        }
    }
   
    // Copy back to circular queue
    queue->front = 0;
    queue->rear = temp_count;
    queue->count = temp_count;
    for (int i = 0; i < temp_count; i++)
    {
        queue->jobs[i] = temp[i];
    }
}

void write_queue_to_log()
{
    pthread_mutex_lock(&queue_mutex);
   
    FILE* log_fp = fopen("queue_log.txt", "a");
    if (!log_fp)
    {
        perror("Log File Error");
        pthread_mutex_unlock(&queue_mutex);
        return;
    }

    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    fprintf(log_fp, "\n====== Queue State at %s ======\n", time_str);
    fprintf(log_fp, "Algorithm: %s | Total Jobs: %d\n",
           queue->current_algorithm == FCFS ? "FCFS" :
           queue->current_algorithm == PRIORITY ? "Priority" : "Round Robin",
           queue->count);

    if (queue->count > 0)
    {
        fprintf(log_fp, "Client\tJob ID\tPriority\tFilename\tArrival\t\tCompletion\t\n");
        fprintf(log_fp, "-------------------------------------------------------------------------------\n");
       
        Job temp_jobs[MAX_JOBS];
        int count = 0;
        for (int i = 0; i < queue->count; i++)
        {
            int idx = (queue->front + i) % MAX_JOBS;
            temp_jobs[count++] = queue->jobs[idx];
        }
       
        if (queue->current_algorithm == PRIORITY)
        {
            for (int i = 0; i < count-1; i++)
            {
                for (int j = 0; j < count-i-1; j++)
                {
                    if (temp_jobs[j].priority > temp_jobs[j+1].priority)
                    {
                        Job swap = temp_jobs[j];
                        temp_jobs[j] = temp_jobs[j+1];
                        temp_jobs[j+1] = swap;
                    }
                }
            }
        }
       
        for (int i = 0; i < count; i++)
        {
            char arrival[30] = "N/A";
            char completion[30] = "Pending";
            int turnaround_time = -1;
            int waiting_time = -1;
           
            if (temp_jobs[i].arrival_time > 0)
            {
                strftime(arrival, sizeof(arrival), "%H:%M:%S",
                        localtime(&temp_jobs[i].arrival_time));
               
                if (temp_jobs[i].completion_time > 0)
                {
                    strftime(completion, sizeof(completion), "%H:%M:%S",
                            localtime(&temp_jobs[i].completion_time));
                }
            }
           
            fprintf(log_fp, "%d\t%d\t%d\t\t%s\t%s\t%s\n",
                   temp_jobs[i].client_socket,
                   temp_jobs[i].jobid,
                   temp_jobs[i].priority,
                   temp_jobs[i].filename,
                   arrival,
                   completion);
        }
    }
    else
    {
        fprintf(log_fp, "Queue is empty\n");
    }
   
    fprintf(log_fp, "====== End Update ======\n");
    fclose(log_fp);
    pthread_mutex_unlock(&queue_mutex);
}


void set_scheduling_algorithm(int algorithm)
{
    pthread_mutex_lock(&queue_mutex);
    queue->current_algorithm = algorithm;
    queue->rr_counter = 0;
    pthread_mutex_unlock(&queue_mutex);
   
    printf("\nScheduling Algorithm set to: ");
    switch(algorithm)
    {
        case FCFS:
        printf("First-Come-First-Serve\n");
        break;
        case ROUND_ROBIN:
        printf("Round Robin\n");
        break;
        case PRIORITY:
        printf("Priority\n");
        break;
        default: printf("Unknown\n");
    }
}

void* handle_client(void* arg)
{
    int client_socket = *(int*)arg;
    struct message msg;
    int job_id = 1;
   
    while (1)
    {
        // Receive message from client
        int bytes_received = recv(client_socket, &msg, sizeof(msg), 0);
        if (bytes_received <= 0)
        {
            printf("Client disconnected\n");
            break;
        }
       
        // Parse the received message into a job
        Job new_job;
        new_job.jobid = job_id++;
        new_job.client_socket = client_socket;
        new_job.job_type = msg.job_type;
        new_job.priority = msg.priority;
        strcpy(new_job.filename, msg.mesfilename);
       
     JobMemory *job_mem = malloc(sizeof(JobMemory));
    job_mem->job_id = new_job.jobid;
    for (int i = 0; i < PAGES_PER_JOB; i++)
    {
        job_mem->pages[i].frame = -1;  
        job_mem->pages[i].is_modified = 0;
    }
    job_memories[new_job.jobid % MAX_JOBS] = job_mem;
    printf("[SERVER] Allocated %d pages for Job %d\n", PAGES_PER_JOB, new_job.jobid);
       
        if (msg.job_type == 1)  // Existing file request
        {
            FILE* fp = fopen(new_job.filename, "r");
            if (fp == NULL)  
            {
                char err_msg[] = "Error: File not found on server.";
                send(client_socket, err_msg, strlen(err_msg), 0);
                continue;
            }

           
            char buffer[MSG_SIZE] = {0};
            fread(buffer, 1, MSG_SIZE - 1, fp);
            fclose(fp);
            send(client_socket, buffer, strlen(buffer), 0);

            // For queue logging
            strcpy(new_job.heading, "EXISTING FILE JOB");
            strcpy(new_job.content, buffer);
        }
        else if (msg.job_type == 2)
        {
            strcpy(new_job.heading, msg.mesheading);
            strcpy(new_job.content, msg.mescontent);
        }
       
        add_job_to_queue(new_job);
       
        printf("\nJob added. View log file? (1 = Yes, 0 = No): ");
        int view_log;
        scanf("%d", &view_log);
        getchar();
       
        if (view_log == 1)
        {
            view_log_file();
        }
        printf("\n📥 [SERVER]: Job Received: ID = %d, Filename = %s\n",new_job.jobid, new_job.filename);
       
       
        if (strcmp(new_job.content, "exit") == 0)
        {
            printf("\n[SERVER]: 'exit' job received from client. Closing connection...\n");
            break;
        }
    }
   
    close(client_socket);
    free(arg);
    return NULL;
}

         


void start_server()
{
    printf("\nSelect Scheduling Algorithm:\n");
    printf("1. First-Come-First-Serve (FCFS)\n");
    printf("2. Round Robin\n");
    printf("3. Priority\n");
    printf("Enter your choice: ");
    int algorithm_choice;
    scanf("%d", &algorithm_choice);
    set_scheduling_algorithm(algorithm_choice);
   
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
   
    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
   
    // Forcefully attach socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
   
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
   
    // Bind the socket to the port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
   
    if (listen(server_fd, MAX_CLIENTS) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
   
    printf("Server listening on port %d...\n", PORT);
   
    // Start worker threads
    pthread_t workers[NUM_THREADS];
    int worker_ids[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++)
    {
        worker_ids[i] = i + 1;
        pthread_create(&workers[i], NULL, worker_thread, &worker_ids[i]);
    }
   
    // Accept incoming connections
    while (1)
    {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }
       
        printf("New connection from %s\n", inet_ntoa(address.sin_addr));
       
        // Create a new thread for each client
        pthread_t thread_id;
        int *client_socket = malloc(sizeof(int));
        *client_socket = new_socket;
       
        if (pthread_create(&thread_id, NULL, handle_client, (void*)client_socket) < 0)
        {
            perror("could not create thread");
            continue;
        }
       
        pthread_detach(thread_id);
    }
 
    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(workers[i], NULL);
    }
   
    close(server_fd);
}

int main()
{
    printf("\n-------------------------------------------------------------------------------------------\n");
    printf("===========================================================================================\n\n");
    printf("\t\t\t\tMULTI-USER PRINT SERVER");
    printf("\n\n===========================================================================================\n");
    printf("-------------------------------------------------------------------------------------------\n\n");
    printf("🖨️  Server is now online and ready to receive print jobs.....\n📡  Waiting for client connections...\n\n");
   
    init_queue();
    memset(phys_mem, 0, sizeof(phys_mem));  // Clear physical memory
    printf("Virtual Memory Ready: %d frames (%d KB total)\n",
           NUM_FRAMES, (NUM_FRAMES * PAGE_SIZE) / 1024);
    start_server();
   
    return 0;
}

--------------------------------------------------------

memory.c

---------------------------------------------------

#include "communication.h"
#include <stdlib.h>

void load_job_pages_into_memory(Job job, int thread_id)
{
    JobMemory *job_mem = job_memories[job.jobid % MAX_JOBS];
    if (!job_mem)
    {
        printf("[THREAD %d] ERROR: No memory allocated for Job %d!\n", thread_id, job.jobid);
        return;
    }

    for (int i = 0; i < PAGES_PER_JOB; i++)
    {
        if (job_mem->pages[i].frame == -1)
        {
            for (int j = 0; j < NUM_FRAMES; j++)
            {
                int is_frame_free = 1;
                for (int k = 0; k < MAX_JOBS; k++)
                {
                    if (job_memories[k])
                    {
                        for (int p = 0; p < PAGES_PER_JOB; p++)
                        {
                            if (job_memories[k]->pages[p].frame == j)
                            {
                                is_frame_free = 0;
                                break;
                            }
                        }
                    }
                }

                if (is_frame_free)
                {
                    job_mem->pages[i].frame = j;
                    used_frames++;
                    printf("[THREAD %d] Loaded Job %d Page %d → Frame %d\n",
                           thread_id, job.jobid, i, j);
                    break;
                }
            }
        }
    }
}
