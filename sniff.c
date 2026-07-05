#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    //TCP만 대상으로
    if (ip->iph_protocol == IPPROTO_TCP) {
      //IP 헤더 길이 계산
      int ip_header_len = ip->iph_ihl * 4;
      //TCP 헤더 파싱
      struct tcpheader *tcp = (struct tcpheader *)((u_char*)ip + ip_header_len);
      //TCP 헤더 길이 계산
      int tcp_header_len = TH_OFF(tcp) * 4;
      //HTTP Message 시작 위치 계산
      u_char *data = (u_char *)tcp + tcp_header_len;

      //데이터 크기 계산
      int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
      int data_len = header->caplen - total_header_len;
      //정보 출력
      printf("==========PACKET==========\n");
      //Ethernet Header
      printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", 
              eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
              eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);  
      printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", 
              eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
              eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);         
      //IP Header
      printf("src ip: %s\n", inet_ntoa(ip->iph_sourceip));
      printf("dst ip: %s\n", inet_ntoa(ip->iph_destip));
      //TCP Header
      printf("src port: %d\n", ntohs(tcp->tcp_sport));
      printf("dst port: %d\n", ntohs(tcp->tcp_dport));
      //HTTP Message
      printf("HTTP Message\n");
      if (data_len > 0){
        for (int i = 0; i < data_len; i++){
          if(isprint(data[i]) || data[i] == '\n' || data[i] == '\r'){
            putchar(data[i]);
          }
          else{
            putchar('.');
          }
        }
        printf("\n");
      }             
      else{
        printf("No data\n");
      } 
      printf("==========================\n");
    }  
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


