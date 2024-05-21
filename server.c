#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


struct arp_d {
  u_int8_t mac_addr[6];
  u_int8_t ip_addr[4];
};

struct arp_d* arp_records;
int array_size;
int records_num = 0;
FILE* fptr;
char* log_file_path = "disapr.log";
char* table_file_path = "disapr.table";
time_t t;

char* mac_to_string(u_int8_t* mac) {
  char* mac_as_string = malloc(17);
  sprintf(mac_as_string, "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2],
    mac[3], mac[4], mac[5]);

  return mac_as_string;
}

char* ip_to_string(u_int8_t* ip) {
  char* str_ip = malloc(16);
  sprintf(str_ip, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return str_ip;
}

void write_table_to_file() {
  fptr = fopen(table_file_path, "w");

  fprintf(fptr, "IP\tMAC\n");
  for(int i = 0; i < records_num; i++) {
    fprintf(fptr, "%s\t%s\n", ip_to_string(arp_records[i].ip_addr), mac_to_string(arp_records[i].mac_addr));
  }
  fclose(fptr); 
}

char* time_string() {
  char* str = malloc(20);
  time(&t);
  struct tm tm = *localtime(&t);
  sprintf(str, "%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  return str;
}


char* record_changed_msg(struct arp_d* arp_data, u_int8_t* old_mac) {
  char* msg = malloc(120);
  sprintf(msg, "%s\tRecord changed\tIP : %s\told MAC : %s\tnew MAC : %s\n",
          time_string(),
          ip_to_string(arp_data->ip_addr),
          mac_to_string(old_mac),
          mac_to_string(arp_data->mac_addr));

  return msg;
}


char* record_added_msg(struct arp_d* arp_data) {
  char* msg = malloc(100);
  sprintf(msg, "%s\tAdded record\tIP : %s\tMAC : %s\n",
          time_string(),
          ip_to_string(arp_data->ip_addr),
          mac_to_string(arp_data->mac_addr));

  return msg;
}

char* incoming_log_msg(struct arp_d* arp_data) {
  char* msg = malloc(100);
  sprintf(msg, "%s\tIncoming\tIP : %s\tMAC : %s\n",
          time_string(),
          ip_to_string(arp_data->ip_addr),
          mac_to_string(arp_data->mac_addr));

  return msg;
}

void increase_array(int size) {
  array_size += size;
  arp_records = realloc(arp_records, sizeof(struct arp_d) * array_size);
}

void check_array_full() {
  if (records_num >= array_size) {
    increase_array(1);
  }
}

void handle_existing_ip (struct arp_d *new_record, struct arp_d *ex_record) {
  if (memcmp(new_record->mac_addr, ex_record->mac_addr, 6) == 0)
    return;

  uint8_t old_mac[6];
  memcpy(old_mac, ex_record->mac_addr, sizeof(ex_record->mac_addr));

  memcpy(ex_record->mac_addr, new_record->mac_addr, sizeof(new_record->mac_addr));
  write_table_to_file();

  printf("%s", record_changed_msg(ex_record, old_mac));
  fptr = fopen(log_file_path, "a");
  fprintf(fptr, "%s", record_changed_msg(ex_record, old_mac));
  fclose(fptr);
}

void add_record (struct arp_d *record) {
  for (int i = 0; i < records_num; i++) {
    if (memcmp(arp_records[i].ip_addr, record->ip_addr, 4) == 0) {
      handle_existing_ip(record, &arp_records[i]);
      return;
    }
  }
  arp_records[records_num] = *record;
  records_num += 1;
  write_table_to_file();
  printf("%s", record_added_msg(record));
  fptr = fopen(log_file_path, "a");
  fprintf(fptr, "%s", record_added_msg(record));
  fclose(fptr); 

  check_array_full();
}

void init_array(int size) {
  array_size = size;
  arp_records = malloc(sizeof(struct arp_d) * size);
}


int main (void)
{ 
  init_array(1);
  socklen_t sl;
  int sfd, cfd, on = 1, n;
  struct sockaddr_in saddr, caddr;
  struct arp_d* arp_data;

  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(2345);
  sfd = socket(PF_INET, SOCK_STREAM, 0);
  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char*) &on, sizeof(on));
  if (bind(sfd, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) {
    perror("Error binding");
    return EXIT_FAILURE;
  }
  listen(sfd, 5);
  while(1) {
    arp_data = malloc(sizeof(struct arp_d));
    if (arp_data == NULL) {
      perror("Faild to allocate memory for incoming meissage");
      continue;
    }

    memset(&caddr, 0, sizeof(caddr));
    sl = sizeof(caddr);
    cfd = accept(sfd, (struct sockaddr*) &caddr, &sl);
    n = read(cfd, arp_data, sizeof(struct arp_d));
    
    if (n < sizeof(struct arp_d)) {
      perror("Invalid incoming msg");
      close(cfd);
      free(arp_data);
      continue;
    }
    
    printf("%s", incoming_log_msg(arp_data));
    
    fptr = fopen(log_file_path, "a");
    fprintf(fptr, "%s", incoming_log_msg(arp_data));
    fclose(fptr); 

    add_record(arp_data);
    close(cfd);
    free(arp_data);
  }
  close(sfd);
  return EXIT_SUCCESS;
}
