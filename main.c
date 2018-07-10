#ifdef _MSC_VER

#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"

int main() {
	FILE *fp;
	//��������ָ�룬�����������е�������������
	pcap_if_t *alldevs;
	//��ǰ����������������
	pcap_if_t *d;
	//��ǰѭ�������
	int inum;
	//��ʼ����ǰ���������Ϊ0
	int i=0;
	//pcap�Ĳ������ݽṹָ��
	pcap_t *adhandle;
	//
	int res;
	//������Ϣ�ַ���
	char errbuf[PCAP_ERRBUF_SIZE];
	//ʱ��ṹ�����
	struct tm *ltime;
	//ʱ���ʽ���ַ���
	char timestr[16];
	//pcap�����ݰ�ͷָ��
	struct pcap_pkthdr *header;
	//��ǰ���������ݰ�
	const u_char *pkt_data;
	//����ʱ��,����
	time_t local_tv_sec;

	int cc = 0;
	fp = fopen("download.txt","w+");
	fclose(fp);
	/* Retrieve the device list */
	//��ȡ�����豸�б�,���ʧ�ܾ����������Ϣ,����ɹ��Ͱ��豸����alldeves,�Ѵ������errbuf
	if(pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr,"Error in pcap findalldevs: %s\n", errbuf);
		return -1;
	}

	/* Print the list */
	//ѭ���оٳ����е�����,���Ұ�ѭ���ĵ�ǰ�������ڵ�ǰ������d��
	for(d=alldevs; d; d=d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	//���û��ѭ��������,��ô���������
	if(i==0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	//��ӡ���˵�ѡ��,���û�ѡ���������
	printf("��ѡ��������ʹ�õ����� (1-%d):",i);
	scanf("%d", &inum);

	//��������������Ų����б���,��ô���˳���
	if(inum < 1 || inum > i) {
		printf("\n�����������������\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	//����ѡ�����������,���Ұ�������Ϊ��ǰ����d
	for(d=alldevs, i=0; i< inum-1 ; d=d->next, i++);

	/* Open the adapter */
	//������,���ҰѴ򿪵Ľ������adhandle��,����򿪴���,��ô�͹ر������б�
	if ((adhandle= pcap_open_live(d->name,	// name of the device
	                              65536,			// portion of the packet to capture.
	                              // 65536 grants that the whole packet will be captured on all the MACs.
	                              1,				// promiscuous mode (nonzero means promiscuous)
	                              1000,			// read timeout
	                              errbuf			// error buffer
	                             )) == NULL) {
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//�������ȷ,�Ϳ�ʼ���һ����Ϣ֮��,��ӡ��������������Ϣ
	printf("\n%s\n���ڼ��� %s...\n�����߲���Ҫ���ص�����\n", pcap_lib_version(),d->description);

	/* At this point, we don't need any more the device list. Free it */
	//alldevs����ָ������Ѿ�������Ҫ��,�ͷ�����,ע��,��ʱ�Ĳ�����������d�Ѿ���֮�����adhandle����
	pcap_freealldevs(alldevs);

	/* Retrieve the packets */
	//��ʼ��adhandle�ж�ȡ����,���ص�����״̬����res��,���res���ڵ���0,�ͼ���,�����˳�
	//����res��״̬��:
	//  1 ��ȡ����
	//  0 ��ȡʱ�䳬ʱ.���������header��pkt_dataָ��ָ��ĵط���Ч(����ʹ��)
	// -1 if an error occurred
	// -2 if EOF was reached reading from an offline capture
/////////////////////////////////////////////////////////////////////�����￪ʼѭ������
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0) {

		if(res == 0)
			/* Timeout elapsed */
			//�����ȡʱ�䳬ʱ,��ô�������ٶ�ȡ
			continue;

		if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00) {

			if(pkt_data[54]==0x47&&pkt_data[55] == 0x45 && pkt_data[56] == 0x54&&pkt_data[58] == 0x2F&&pkt_data[59] == 0x32) {

				for (i=54; i<100; i++) {
					if(pkt_data[i] != 0x2E) {
						if(pkt_data[i+1] != 0x6D) {
							if(pkt_data[i+2] != 0x70) {
								if(pkt_data[i+3] != 0x33) {
									printf("��ǰ��������\n");
									printf("Դ��ַ:");
									cc = i+4;
									for(i; i<100; i++)
										printf("%c", (char)pkt_data[i+3]);
									printf(".mp3\n");
								}
							}
						}
					}
				}

				if(pkt_data[54]==0x47&&pkt_data[55] == 0x45 && pkt_data[56] == 0x54&&pkt_data[58] == 0x2F&&pkt_data[59] == 0x32) {

					for (i=54; i<200; i++) {
						if(pkt_data[i] == 0x48&&pkt_data[i+1] == 0x6F&&pkt_data[i+2] == 0x73&&pkt_data[i+3] == 0x74&&pkt_data[i+4] == 0x3A&&pkt_data[i+6] == 0x6D) { //H
							printf("������������·��: ");
							printf("m7c.music.126.net");
							fp = fopen("download.txt","a+");
							fprintf(fp,"m7c.music.126.net");
							for(cc; cc<300; cc++) {
								if(pkt_data[cc] == 0x2E&&pkt_data[cc+1] == 0x6D&&pkt_data[cc+2] == 0x70&&pkt_data[cc+3] == 0x33)//.mp3
									break;
								else {
									printf("%c", (char)pkt_data[cc]);
									fprintf(fp,"%c",(char)pkt_data[cc]);
								}
							}
							fprintf(fp,".mp3\n\n");
							printf(".mp3\n");
							printf("���download�ļ�������������\n\n");
							fclose(fp);
							//������ĵĻ����Կ��ǻ�Ա��Դ�Զ�����
						}
					}
				}
			}
		}
		if(res == -1) {
			printf("��ȡ���ݰ�����: %s\n", pcap_geterr(adhandle));
			return -1;
		}

	}

	//���resΪ-1�Ļ�,���������ӿڳ�����,���ܼ�����,�Ѵ����ӡ�����Ϳ�����

	//���չر�adhandle��Ӧ���������ͷ���Դ
	pcap_close(adhandle);
	return 0;
}

