//PEtool.cpp		
// �����ڻ��������ƣ���������ͷ�����������ݣ�									
#include "Global.h"
#include <stdio.h>

int main()
{
	//TestPrintPEHeader("E:\\����\\fg.exe"); //���Գɹ�2024/5/25(2024/5/31 20:18�޸ģ��ͷ�������ڴ�֮��ʹ�ø��ڴ�ָ���ÿ�)

	//TestPELoader(); //2024/5/31 20:43 �Ż��ڴ����

	//TestAddCodeInCodeSec();  //2024/5/31 20:46 �Ż��ڴ����
	
	//TestAddCodeInDataSec(3); //��������SizeOfRawDataС��VirtualSize,������Ӵ������  //2024/5/31 20:50 �Ż��ڴ����

	//TestAddCodeInNewSec();  //2024/5/31 20:53 �Ż��ڴ����

	//TestAddCodeInExpSec(0x200); //2024/5/31 20:56 �Ż��ڴ����

	//TestMergeSec();  //2024/5/31 20:58 �Ż��ڴ����

	//TestPrintDirectory(); //2024/5/31 20:59 �Ż��ڴ����

	//TestPrintExportTable();  //2024/5/31 21:03 �Ż��ڴ����

	//TestGetFunctionAddr();  //2024/6/7 12:43���Գɹ�

	//TestPrintRelocation();   //2024/5/31 21:06 �Ż��ڴ����

	//moveExportTable();  //2024/6/6 17:47���Գɹ�

	//moveRelocationTable();  //2024/6/6 17:47���Գɹ�

	//TestPrintImportTable(); //���Գɹ�

	//TestPrintBoundImportTable(); //δ���ԣ�û�в��Գ���Ŀǰ�󶨵��������Ѿ�����

	injectByImportTable();  //2024/6/10 14:40���Գɹ�
	return 0;
}