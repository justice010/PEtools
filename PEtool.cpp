//PEtool.cpp		
// 新增节还可以完善（比如提升头挤掉垃圾数据）									
#include "Global.h"
#include <stdio.h>

int main()
{
	//TestPrintPEHeader("E:\\逆向\\fg.exe"); //测试成功2024/5/25(2024/5/31 20:18修改：释放申请的内存之后，使得该内存指针置空)

	//TestPELoader(); //2024/5/31 20:43 优化内存回收

	//TestAddCodeInCodeSec();  //2024/5/31 20:46 优化内存回收
	
	//TestAddCodeInDataSec(3); //第三节中SizeOfRawData小于VirtualSize,导致添加代码出错  //2024/5/31 20:50 优化内存回收

	//TestAddCodeInNewSec();  //2024/5/31 20:53 优化内存回收

	//TestAddCodeInExpSec(0x200); //2024/5/31 20:56 优化内存回收

	//TestMergeSec();  //2024/5/31 20:58 优化内存回收

	//TestPrintDirectory(); //2024/5/31 20:59 优化内存回收

	//TestPrintExportTable();  //2024/5/31 21:03 优化内存回收

	//TestGetFunctionAddr();  //2024/6/7 12:43测试成功

	//TestPrintRelocation();   //2024/5/31 21:06 优化内存回收

	//moveExportTable();  //2024/6/6 17:47测试成功

	//moveRelocationTable();  //2024/6/6 17:47测试成功

	//TestPrintImportTable(); //测试成功

	//TestPrintBoundImportTable(); //未测试，没有测试程序，目前绑定导入表基本已经废弃

	injectByImportTable();  //2024/6/10 14:40测试成功
	return 0;
}