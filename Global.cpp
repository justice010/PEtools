//Global.cpp
#include "Global.h"
#include <stdio.h>
#include <stdlib.h>

#define FILEPATH_IN "E:\\逆向\\fg.exe"
#define FILEPATH_IN_DLL "E:\\逆向\\Mydll.dll"
#define FILEPATH_OUT "E:\\逆向\\fg_new.exe"
#define FILEPATH_OUT_DLL "E:\\逆向\\Mydll_new.dll"
#define FILEPATH "E:\\逆向\\injectDll.dll"
#define SHELLCODELEN 0x12
#define MESSAGEBOXADDR 0x76A4A740

//全局变量
BYTE shellcode[] =
{
	0x6A,00,0x6A,00,0x6A,00,0x6A,00,
	0xE8,00,00,00,00,
	0xE9,00,00,00,00
};


DWORD ReadPEFile(IN const char* lpszFile, OUT void** pFileBuffer)
{
	if (lpszFile == nullptr)
	{
		printf("无效的输入参数！\n");
		return 0;
	}

	//打开文件
	FILE* pFile = fopen(lpszFile, "rb");
	if (pFile == nullptr)
	{
		printf("无法打开文件：%s\n",lpszFile);
		return 0;
	}

	//获取文件大小
	fseek(pFile, 0, SEEK_END);
	DWORD fileSize = ftell(pFile);
	rewind(pFile);

	//申请内存空间
	void* pTempFileBuffer = malloc(fileSize);
	if (pTempFileBuffer == nullptr)
	{
		printf("申请内存失败！\n");
		fclose(pFile);
		return 0;
	}

	//初始化内存空间
	memset(pTempFileBuffer, 0, fileSize);

	//将文件数据读取到缓冲区
	size_t bytesRead = fread(pTempFileBuffer, 1, fileSize, pFile);
	if (bytesRead != fileSize)
	{
		printf("读取文件数据失败！\n");
		free(pTempFileBuffer);
		fclose(pFile);
		return 0;
	}

	//关闭文件
	*pFileBuffer = pTempFileBuffer;
	fclose(pFile);

	return fileSize;
}

void TestPrintPEHeader(const char* lpszFile)
{
	if (lpszFile == nullptr)
	{
		printf("无效的输入参数！\n");
	}

	void* pFileBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOS头										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NT头(包括标准PE头和可选PE头)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //标准PE头										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //可选PE头										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //节表	


	DWORD fileSize = ReadPEFile(lpszFile, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件失败！\n");
		return ;
	}

	//判断MZ标志
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//判断PE标志
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//打印PE头信息
	printf("***************************DOS头***************************\n");
	printf("e_magic:%x\n", pDosHeader->e_magic);
	printf("e_lfanew:%x\n", pDosHeader->e_lfanew);

	printf("***************************PE头标志***************************\n");
	printf("PE标志：%x\n", pNTHeader->Signature);

	printf("***************************标准PE头***************************\n");
	printf("Machine:%x\n", pPEHeader->Machine);
	printf("节的数量:%x\n", pPEHeader->NumberOfSections);
	printf("可选PE头的大小:%x\n", pPEHeader->SizeOfOptionalHeader);

	printf("***************************可选PE头***************************\n");
	printf("程序入口点偏移:%x\n", pOptionalHeader->AddressOfEntryPoint);
	printf("内存对齐:%x\n", pOptionalHeader->SectionAlignment);
	printf("文件对齐:%x\n", pOptionalHeader->FileAlignment);
	printf("SizeOfHeaders:%x\n", pOptionalHeader->SizeOfHeaders);

	printf("***************************节表***************************\n");
	for (int i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeader++)
	{
		printf("节名称：%s\n", pSectionHeader->Name);
		printf("VirtualSize:%x\n", pSectionHeader->Misc.VirtualSize);
		printf("VirtualAddress:%x\n", pSectionHeader->VirtualAddress);
		printf("SizeOfRawData:%x\n", pSectionHeader->SizeOfRawData);
		printf("PointerToRawData:%x\n", pSectionHeader->PointerToRawData);
		printf("\n");
	}

	free(pFileBuffer);
	pFileBuffer = nullptr;
}

DWORD CopyFileBufferToImageBuffer(IN const void* pFileBuffer, OUT void** pImageBuffer)
{
	void* pTempImageBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOS头										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NT头(包括标准PE头和可选PE头)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //标准PE头										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //可选PE头										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //节表	

	
	if (pFileBuffer == nullptr)
	{
		printf("缓冲区指针无效！\n");
		return 0;
	}

	//判断是否是有效的MZ标志
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志！\n");
		return 0;
	}
	//判断是否是有效的PE标志
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志！\n");
		return 0;
	}
	pPEHeader = &pNTHeader->FileHeader;
	//可选PE头
	pOptionalHeader = &pNTHeader->OptionalHeader;
	//第一个节表的指针
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//根据SizeOfImage申请内存空间
	pTempImageBuffer = malloc(pOptionalHeader->SizeOfImage);
	if (pTempImageBuffer == nullptr)
	{
		printf("分配缓冲区内存空间失败！\n");
		return 0;
	}

	//初始化缓冲区
	memset(pTempImageBuffer, 0, pOptionalHeader->SizeOfImage);

	//将FileBuffer中的PE头复制到ImageBuffer
	memcpy(pTempImageBuffer, pDosHeader, pOptionalHeader->SizeOfHeaders);

	//将FileBuffer中的各个节复制到ImageBuffer
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++, pTempSectionHeader++)
	{
		memcpy((void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress),
			   (void*)((DWORD)pDosHeader + pTempSectionHeader->PointerToRawData),
			   max(pTempSectionHeader->SizeOfRawData, pTempSectionHeader->Misc.VirtualSize));
	}

	//返回数据
	*pImageBuffer = pTempImageBuffer;
	return pOptionalHeader->SizeOfImage;
}


DWORD CopyImageBufferToNewBuffer(IN const void* pImageBuffer, OUT void** pNewBuffer)
{
	void* pTempNewBuffer = nullptr;
	DWORD newSize = 0;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOS头										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NT头(包括标准PE头和可选PE头)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //标准PE头										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //可选PE头										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //节表	


	if (pImageBuffer == nullptr)
	{
		printf("缓冲区指针无效！\n");
		return 0;
	}

	//判断是否是有效的MZ标志
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志");
		return 0;
	}
	//判断是否是有效的PE标志
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志！\n");
		return 0;
	}
	pPEHeader = &pNTHeader->FileHeader;
	//可选PE头
	pOptionalHeader = &pNTHeader->OptionalHeader;
	//第一个节表的指针
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//ImageBuffer到最后一个节的开始加最后一个节的大小
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	newSize = (pLastSectionHeader->PointerToRawData) + (pLastSectionHeader->SizeOfRawData);

	//分配缓冲区内存空间
	pTempNewBuffer = malloc(newSize);
	if (pTempNewBuffer == nullptr)
	{
		printf("分配缓冲区空间失败！\n");
		return 0;
	}

	//初始化缓冲区
	memset(pTempNewBuffer, 0, newSize);

	//将ImageBuffer中的PE头复制到NewBuffer
	memcpy(pTempNewBuffer, pImageBuffer, pOptionalHeader->SizeOfHeaders);

	//将各个节按文件对齐的方式从ImageBuffer中的PE头复制到NewBuffer
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++, pTempSectionHeader++)
	{
		memcpy((void*)((DWORD)pTempNewBuffer + pTempSectionHeader->PointerToRawData),
			   (void*)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress),
			   max(pTempSectionHeader->SizeOfRawData, pTempSectionHeader->Misc.VirtualSize));
	}

	//返回数据
	*pNewBuffer = pTempNewBuffer;
	return newSize;
}

BOOL MemoryTOFile(IN const void* pMemBuffer, IN size_t size, OUT const char* lpszFile)
{
	if (pMemBuffer == nullptr || size == 0)
	{
		printf("无效的输入参数！\n");
		return 0;
	}

	FILE* pFile = fopen(lpszFile, "wb");
	if (pFile == nullptr)
	{
		return 0;
	}

	//从数据写入文件
	size_t written = fwrite(pMemBuffer, 1, size, pFile);

	//检查写入是否成功
	if (written != size)
	{
		printf("写入数据时发生错误！\n");
		fclose(pFile);
		return FALSE;
	}

	fclose(pFile);

	return written;
}

DWORD RvaToFileOffset(IN const void* pFileBuffer, IN DWORD dwRva)
{
	//检查输入参数
	if (pFileBuffer == nullptr || dwRva == 0)
	{
		printf("无效的输入参数！\n");
		return 0;
	}

	//解析DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		return 0;
	}

	//解析NT头
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		return 0;
	}

	//获取节表
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)&pNTHeader->OptionalHeader + pNTHeader->FileHeader.SizeOfOptionalHeader);
	
	//遍历所有节，找到Rva所在节
	PIMAGE_SECTION_HEADER targetSection = nullptr;
	for (WORD i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
	{
		DWORD sectionVAStart = pSectionHeader[i].VirtualAddress;
		DWORD sectionVAEnd = pSectionHeader[i].VirtualAddress + max(pSectionHeader[i].SizeOfRawData, pSectionHeader[i].Misc.VirtualSize);
		
		if (dwRva >= sectionVAStart && dwRva <= sectionVAEnd)
		{
			targetSection = &pSectionHeader[i];
			break;
		}
	}

	if (targetSection == nullptr)
	{
		printf("没有找到对应的节！\n");
		return 0;
	}

	//地址转换
	DWORD sectionOffset = dwRva - targetSection->VirtualAddress;
	DWORD dwFoa = targetSection->PointerToRawData + sectionOffset;

	return dwFoa;
}

void recycleMemory(void** pFileBuffer, void** pImageBuffer, void** pNewBuffer)
{
	if (*pFileBuffer != nullptr)
	{
		free(*pFileBuffer);
		*pFileBuffer = nullptr;
	}
	if (*pImageBuffer != nullptr)
	{
		free(*pImageBuffer);
		*pImageBuffer = nullptr;
	}
	if (*pNewBuffer != nullptr)
	{
		free(*pNewBuffer);
		*pNewBuffer = nullptr;
	}
}

void TestPELoader()
{
	void* pFileBuffer = nullptr;
	void* pImageBuffer = nullptr;
	void* pNewBuffer = nullptr;

	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件失败！\n");
		return ;
	}

	DWORD filebufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (filebufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBuffer失败！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	DWORD size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || pNewBuffer == nullptr)
	{
		printf("ImageBuffer--->NewBuffer失败！\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}

	BOOL isOK = FALSE;
	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if (isOK)
	{
		printf("存盘成功！\n");
	}
	else
	{
		printf("存盘失败！\n");
	}

	recycleMemory(&pFileBuffer, &pImageBuffer, &pNewBuffer);
}

void TestAddCodeInCodeSec()
{
	void* pFileBuffer = nullptr;
	void* pImageBuffer = nullptr;
	void* pNewBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOS头										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NT头(包括标准PE头和可选PE头)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //标准PE头										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //可选PE头										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //节表	
	PBYTE codeBegin = nullptr;
	BOOL isOK = FALSE;
	DWORD size = 0;

	//File--->FileBuffer
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("文件--->缓冲区失败！\n");
		return ;
	}

	//FileBuffer--->ImageBuffer
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBuffer失败！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//判断代码段空闲区是否足够存储ShellCode代码
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	if ((pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize) < SHELLCODELEN)
	{
		printf("代码空闲空间不足");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}

	//将代码复制到空闲区
	codeBegin = (PBYTE)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	memcpy(codeBegin, shellcode, SHELLCODELEN);
	
	//修正E8
	DWORD callAddr = MESSAGEBOXADDR - (pOptionalHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)(pImageBuffer)));
	*(PDWORD)(codeBegin + 9) = callAddr;

	//修正E9
	DWORD jmpAddr = (pOptionalHeader->ImageBase + pOptionalHeader->AddressOfEntryPoint) - (pOptionalHeader->ImageBase + ((DWORD)(codeBegin + SHELLCODELEN) - (DWORD)(pImageBuffer)));
	*(PDWORD)(codeBegin + 0xE) = jmpAddr;
	
	//修改OEP
	pOptionalHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pImageBuffer;

	//ImageBuffer--->NewBuffer
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || pNewBuffer == nullptr)
	{
		printf("ImageBuffer--->NewBuffer失败！\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}
	//NewBuffer--->文件
	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if (isOK)
	{
		printf("存盘成功！\n");
	}
	else
	{
		printf("存盘失败！\n");
	}

	//释放内存
	recycleMemory(&pFileBuffer, &pImageBuffer, &pNewBuffer);
}

void TestAddCodeInDataSec(WORD sectionIndex)
{
	void* pFileBuffer = nullptr;
	void* pImageBuffer = nullptr;
	void* pNewBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOS头										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NT头(包括标准PE头和可选PE头)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //标准PE头										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //可选PE头										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //节表	
	PBYTE codeBegin = nullptr;
	BOOL isOK = FALSE;
	DWORD size = 0;

	//File--->FileBuffer
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("文件--->缓冲区失败！\n");
		return ;
	}

	//FileBuffer--->ImageBuffer
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBuffer失败！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//判断代码段空闲区是否足够存储ShellCode代码
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	if (sectionIndex > pPEHeader->NumberOfSections)
	{
		printf("没有此节！\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}
	PIMAGE_SECTION_HEADER pSectionHeaderX = pSectionHeader + (sectionIndex - 1); //第section个节的节表位置
	if ((pSectionHeaderX->SizeOfRawData - pSectionHeaderX->Misc.VirtualSize) < SHELLCODELEN)
	{
		printf("此节空闲空间不足！\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}
	
	//将shellcode代码复制到此节的空闲区
	codeBegin = (PBYTE)((DWORD)(pImageBuffer) + pSectionHeaderX->VirtualAddress + pSectionHeaderX->Misc.VirtualSize);
	memcpy(codeBegin, shellcode, SHELLCODELEN);

	//修正E8
	DWORD callAddr = MESSAGEBOXADDR - (pOptionalHeader->ImageBase + (DWORD)(codeBegin + 0xD) - (DWORD)(pImageBuffer));
	*((PDWORD)(codeBegin + 0x9)) = callAddr;
	
	//修正E9
	DWORD jmpAddr = (pOptionalHeader->ImageBase + pOptionalHeader->AddressOfEntryPoint) - (pOptionalHeader->ImageBase + (DWORD)(codeBegin + SHELLCODELEN) - (DWORD)(pImageBuffer));
	*((PDWORD)(codeBegin + 0xE)) = jmpAddr;

	//修改OEP
	pOptionalHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pImageBuffer;

	//添加可执行权限
	pSectionHeaderX->Characteristics |= IMAGE_SCN_MEM_EXECUTE;


	//ImageBuffer--->NewBuffer
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if(!size || pNewBuffer == nullptr)
	{
		printf("ImageBuffer--->NewBuffer失败！\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}

	//NewBuffer--->文件
	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if (isOK)
	{
		printf("存盘成功！\n");
	}

	//释放内存
	recycleMemory(&pFileBuffer, &pImageBuffer, &pNewBuffer);
}


int Align(int x, int y)
{
	if (x <= y)
	{
		return y;
	}
	else
	{
		if (x % y == 0)
		{
			return x;
		}
		return (x / y + 1) * y;
	}
}

void TestAddCodeInNewSec()
{
	void* pFileBuffer = nullptr;
	void* pImageBuffer = nullptr;
	void* pNewImageBuffer = nullptr;
	void* pNewBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOS头										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NT头(包括标准PE头和可选PE头)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //标准PE头										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //可选PE头										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //节表	
	PBYTE codeBegin = nullptr;
	BOOL isOK = FALSE;
	DWORD size = 0;

	//文件--->缓冲区
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("文件--->缓冲区失败！\n");
		return ;
	}

	//FileBuffer--->ImageBuffer
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBuffer失败！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//判断是否有足够的空间添加一个节表
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;
	PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);

	if (pOptionalHeader->SizeOfHeaders - ((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("空闲空间不够，无法添加节表！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//新增一个节的数据
	pNewImageBuffer = malloc(_msize(pImageBuffer) + 0x1000);
	if (pNewImageBuffer == nullptr)
	{
		printf("申请内存空间失败！\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return;
	}

	//节的数量+1
	pPEHeader->NumberOfSections += 1;

	//改变SizeOfImage
	pOptionalHeader->SizeOfImage += 0x1000;

	memset(pNewImageBuffer, 0, _msize(pNewImageBuffer));
	memcpy_s(pNewImageBuffer, _msize(pNewImageBuffer), pImageBuffer, _msize(pImageBuffer));

	pDosHeader = (PIMAGE_DOS_HEADER)pNewImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 2;
	pNewSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;

	//新增一个节表(复制第一个节表)
	memcpy(pNewSectionHeader, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	//在新增节表后面填充一个节表大小的0
	memset((void*)((DWORD)pNewSectionHeader + IMAGE_SIZEOF_SECTION_HEADER), 0, IMAGE_SIZEOF_SECTION_HEADER);


	//修改新增节表的属性
	strncpy((char *)pNewSectionHeader->Name, ".newsec", IMAGE_SIZEOF_SHORT_NAME);
	pNewSectionHeader->Misc.VirtualSize = 0x1000;
	pNewSectionHeader->VirtualAddress = pLastSectionHeader->VirtualAddress + (DWORD)Align(max(pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->SizeOfRawData), pOptionalHeader->SectionAlignment);
	pNewSectionHeader->SizeOfRawData = 0x1000;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	/*
	//在新增节中插入shellcode并修正E8 E9
	codeBegin = (PBYTE)((DWORD)pNewImageBuffer + pNewSectionHeader->VirtualAddress);
	memset(codeBegin, 0, 0x1000);
	memcpy(codeBegin, shellcode, SHELLCODELEN);

	DWORD callAddr = MESSAGEBOXADDR - (pOptionalHeader->ImageBase + (DWORD)(codeBegin + 0xD) - (DWORD)(pNewImageBuffer));
	*((PDWORD)(codeBegin + 0x9)) = callAddr;

	DWORD jmpAddr = (pOptionalHeader->ImageBase + pOptionalHeader->AddressOfEntryPoint) - (pOptionalHeader->ImageBase + (DWORD)(codeBegin + SHELLCODELEN) - (DWORD)(pNewImageBuffer));
	*((PDWORD)(codeBegin + 0xE)) = jmpAddr;

	pOptionalHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pNewImageBuffer;*/
	
	size = CopyImageBufferToNewBuffer(pNewImageBuffer, &pNewBuffer);
	if (size == 0 || pNewBuffer == NULL)
	{
		printf("NewImageBuffer--->NewBuffer失败！\n");
		recycleMemory(&pFileBuffer, &pImageBuffer, &pNewImageBuffer);
		return ;
	}

	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if(isOK)
	{
		printf("存盘成功！\n");
	}

	//释放内存
	recycleMemory(&pFileBuffer, &pImageBuffer, &pNewImageBuffer);
	free(pNewBuffer);
	pNewBuffer = nullptr;
}

void TestAddCodeInExpSec(size_t expSize)
{
	void* pFileBuffer = nullptr;
	void* pImageBuffer = nullptr;
	void* newBuffer = nullptr;
	void* pNewBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOS头
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NT头(包括标准PE头和可选PE头)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //标准PE头										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //可选PE头										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //节表	
	BOOL isOK = FALSE;
	DWORD size = 0;


	//文件--->缓冲区
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("文件--->缓冲区失败！\n");
		return ;
	}

	//FileBuffer--->ImageBuffer
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBuffer失败！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//解析PE头
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);

	//分配新的内存
	newBuffer = malloc(pOptionalHeader->SizeOfImage + expSize);
	if (newBuffer == nullptr)
	{
		printf("申请内存空间失败！\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}
	memset(newBuffer, 0, pOptionalHeader->SizeOfImage + expSize);

	//修改扩大节之后的节表属性和
	DWORD tempSize = (DWORD)Align(pLastSectionHeader->Misc.VirtualSize, pOptionalHeader->SectionAlignment) + expSize;
	pLastSectionHeader->SizeOfRawData = tempSize;
	pLastSectionHeader->Misc.VirtualSize = tempSize;
	pOptionalHeader->SizeOfImage += expSize;

	memcpy(newBuffer, pImageBuffer, pOptionalHeader->SizeOfImage - expSize);

	//newBuffer--->NewBuffer
	size = CopyImageBufferToNewBuffer(newBuffer, &pNewBuffer);
	if (size == 0 || pNewBuffer == nullptr)
	{
		printf("newBuffer--->NewBuffer失败！\n");
		recycleMemory(&pFileBuffer, &pImageBuffer, &newBuffer);
		return ;
	}

	//存盘
	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if (isOK)
	{
		printf("存盘成功！\n");
	}

	//释放内存
	recycleMemory(&pFileBuffer, &pImageBuffer, &newBuffer);
	free(pNewBuffer);
	pNewBuffer = nullptr;
}

void TestMergeSec()
{
	void* pFileBuffer = nullptr;
	void* pImageBuffer = nullptr;
	void* pNewBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOS头
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NT头(包括标准PE头和可选PE头)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //标准PE头										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //可选PE头										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //节表	
	BOOL isOK = FALSE;
	DWORD size = 0;

	//文件--->缓冲区
	DWORD fileSize =  ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("文件--->缓冲区失败！\n");
		return ;
	}

	//FileBuffer--->
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBuffer失败！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	// 解析PE头
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//修改第一个节的属性
	DWORD alignedSizeOfHeaders = Align(pOptionalHeader->SizeOfHeaders, pOptionalHeader->SectionAlignment);
	DWORD newSizeOfRawData = pOptionalHeader->SizeOfImage - alignedSizeOfHeaders;
	pSectionHeader->SizeOfRawData = newSizeOfRawData;
	pSectionHeader->Misc.VirtualSize = newSizeOfRawData;

	//节的数量设为1
	pPEHeader->NumberOfSections = 1;

	//修改节权限
	pSectionHeader->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	pSectionHeader->Characteristics |= IMAGE_SCN_MEM_READ;
	pSectionHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;

	//ImageBuffer--->NewBuffer
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || pNewBuffer == NULL)
	{
		printf("ImageBuffer--->NewBuffer失败！\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}

	//存盘
	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if (isOK)
	{
		printf("存盘成功！\n");
	}
	else
	{
		printf("存盘失败！\n");
	}

	//释放内存
	recycleMemory(&pFileBuffer, &pImageBuffer, &pNewBuffer);
}

void TestPrintDirectory()
{
	void* pFileBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOS头
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NT头(包括标准PE头和可选PE头)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //标准PE头										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //可选PE头										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //节表	

	DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件失败！\n");
		return ;
	}

	pDosHeader = PIMAGE_DOS_HEADER(pFileBuffer);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的的MZ标志！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ; 
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE标志！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//打印目录表
	printf("导出表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	printf("导入表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	printf("资源表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
	printf("异常信息表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
	printf("安全证书表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
	printf("重定位表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	printf("调试信息表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	printf("版权所有表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
	printf("全局指针表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
	printf("TLS表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
	printf("加载配置表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
	printf("绑定导入表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
	printf("IAT表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
	printf("延迟导入表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
	printf("COM信息表：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);
	printf("保留：VirtualAddress:%x，size:%x\n", pOptionalHeader->DataDirectory[15].VirtualAddress, pOptionalHeader->DataDirectory[15].Size);
	
	//释放内存
	free(pFileBuffer);
	pFileBuffer = nullptr;
}

void TestPrintExportTable()
{
	void* pFileBuffer = nullptr;

	//读取文件到缓冲区
	 DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件失败！\n");
		return ;
	}

	//解析DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//解析NT头
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//获取导出表地址
	DWORD exportTableVAddress = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportTableFAddress = RvaToFileOffset(pFileBuffer, exportTableVAddress);
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportTableFAddress);

	//打印导出表所有信息
	printf("保留字段(Characteristics):%x\n", pExportTable->Characteristics);
	printf("导出表生成的时间戳(TimeDateStamp):%x\n", pExportTable->TimeDateStamp);
	printf("导出表的主版本号(MajorVersion):%x\n", pExportTable->MajorVersion);
	printf("导出表的次版本号(MinorVersion):%x\n", pExportTable->MinorVersion);
	printf("------------------------------------------------------------------\n");

	DWORD fileOffsetOfName = RvaToFileOffset(pFileBuffer, pExportTable->Name);
	printf("模块名称的FOA(fileOffsetOfName):%x\n", fileOffsetOfName);
	printf("模块名称的RVA(Name):%x\n", pExportTable->Name);
	printf("模块名称：%s\n", (char*)((DWORD)pFileBuffer + fileOffsetOfName));
	printf("导出函数的起始序号(Base):%x\n", pExportTable->Base);
	printf("导出函数的总数(NumberOfFunctions):%x\n", pExportTable->NumberOfFunctions);
	printf("导出名称的总数(NumberOfNames):%x\n", pExportTable->NumberOfNames);
	printf("------------------------------------------------------------------\n");

	DWORD fileOffsetOfFunctions = RvaToFileOffset(pFileBuffer, pExportTable->AddressOfFunctions);
	DWORD fileOffsetOfNames = RvaToFileOffset(pFileBuffer, pExportTable->AddressOfNames);
	DWORD fileOffsetOfNameOrdinals = RvaToFileOffset(pFileBuffer, pExportTable->AddressOfNameOrdinals);
	printf("导出函数地址数组的起始地址(RVA)(AddressOfFunctions):%x\n", pExportTable->AddressOfFunctions);
	printf("导出名称数组的起始地址(RVA)(AddressOfNames):%x\n", pExportTable->AddressOfNames);
	printf("导出名称序号数组的起始地址(RVA)(AddressOfNameOrdinals):%x\n", pExportTable->AddressOfNameOrdinals);
	printf("------------------------------------------------------------------\n");
	printf("导出函数地址数组的起始地址(FOA)(fileOffsetOfFunctions):%x\n", fileOffsetOfFunctions);
	printf("导出名称数组的起始地址(FOA)(fileOffsetOfNames):%x\n", fileOffsetOfNames);
	printf("导出名称序号数组的起始地址(FOA)(fileOffsetOfNameOrdinals):%x\n", fileOffsetOfNameOrdinals);

	// 获取导出表中的地址
	PDWORD addressOfNames = (PDWORD)((DWORD)pFileBuffer + fileOffsetOfNames);
	PWORD addressOfNameOrdinals = (PWORD)((DWORD)pFileBuffer + fileOffsetOfNameOrdinals);
	PDWORD addressOfFunctions = (PDWORD)((DWORD)pFileBuffer + fileOffsetOfFunctions);

	printf("------------------------------------------------------------------\n");
	// 打印所有导出函数的名称、地址和序号
	for (DWORD i = 0; i < pExportTable->NumberOfNames; i++)
	{
		DWORD functionNameRVA = addressOfNames[i];
		DWORD functionNameFOA = RvaToFileOffset(pFileBuffer, functionNameRVA);
		char* funcName = (char*)((DWORD)pFileBuffer + functionNameFOA);
		WORD ordinal = addressOfNameOrdinals[i] + pExportTable->Base;
		DWORD functionRVA = addressOfFunctions[addressOfNameOrdinals[i]];
		DWORD functionFOA = RvaToFileOffset(pFileBuffer, functionRVA);
		printf("函数名: %s, 函数序号: %d, 函数地址: %x\n", funcName, ordinal, functionFOA);
	}

	free(pFileBuffer);
	pFileBuffer = nullptr;
}

DWORD GetFunctionAddrByName(IN const void* pFileBuffer, IN const char* functionName)
{
	if (pFileBuffer == nullptr)
	{
		printf("缓冲区指针无效！\n");
		return 0;
	}

	//解析PE头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		return 0;
	}
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if(pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		return 0;
	}

	//找到导出表
	DWORD exportTableRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportTableFOA = RvaToFileOffset(pFileBuffer, exportTableRVA);
	if (exportTableFOA == 0)
	{
		printf("无效的导出表 RVA！\n");
		return 0;
	}
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportTableFOA);


	//根据函数名找出函数地址
	PDWORD addressOfName = (PDWORD)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportTable->AddressOfNames));
	PWORD addressOfNameOrdinals = (PWORD)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportTable->AddressOfNameOrdinals));
	PDWORD addressOfFuncitons = (PDWORD)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportTable->AddressOfFunctions));
	for (DWORD i = 0; i < pExportTable->NumberOfNames; i++)
	{	
		DWORD functionNameRVA = addressOfName[i];
		DWORD functionNameFOA = RvaToFileOffset(pFileBuffer, functionNameRVA);
		char* funcName = (char*)((DWORD)pFileBuffer + functionNameFOA);
		if (strcmp(funcName, functionName) == 0)
		{
			DWORD funcRVA = addressOfFuncitons[addressOfNameOrdinals[i]];
			return funcRVA;
		}
	}
	return 0;
}

DWORD GetFunctionAddrByOrdinals(IN const void* pFileBuffer, IN DWORD ordinal)
{
	if (pFileBuffer == nullptr)
	{
		printf("无效的缓冲区指针！\n");
		return 0;
	}
	
	//解析PE头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		return 0;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		return 0;
	}
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;

	//找出导出表
	DWORD exportTableRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportTableFOA = RvaToFileOffset(pFileBuffer, exportTableRVA);
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportTableFOA);

	//确保到处序号在范围内
	if (ordinal < pExportTable->Base || ordinal >= pExportTable->Base + pExportTable->AddressOfFunctions)
	{
		printf("无效的导出序号！\n");
		return 0;
	}

	//根据导出序号找出函数地址
	DWORD exportOrdinal = ordinal - pExportTable->Base;
	PDWORD addressOfNameOrdinals = (PDWORD)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportTable->AddressOfNameOrdinals));
	PDWORD addressOfFunction = (PDWORD)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportTable->AddressOfFunctions));

	DWORD funcRVA = addressOfFunction[exportOrdinal];

	return funcRVA;
}

void TestGetFunctionAddr()
{
	void* pFileBuffer = nullptr;

	//加载dll文件
	DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("加载DLL失败！\n");
		return ; 
	}

	//获取函数地址并打印
	DWORD funcAddr = GetFunctionAddrByName(pFileBuffer, "_Plus@8");
	printf("%x\n", funcAddr);

	free(pFileBuffer);
	pFileBuffer = nullptr;
}

void TestPrintRelocation()
{
	void* pFileBuffer = nullptr;
	DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件失败！\n");
		return ;
	}

	//解析PE头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ; 
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//找到重定位表
	DWORD relocationTableRVA =  pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD relocationTableFOA = RvaToFileOffset(pFileBuffer, relocationTableRVA);
	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + relocationTableFOA);


	//打印重定位表所有信息
	while (pRelocationTable->VirtualAddress != 0 && pRelocationTable->SizeOfBlock != 0)
	{
		printf("VirtualAddress:%x\n", pRelocationTable->VirtualAddress);
		printf("SizeOfBlock:%x\n", pRelocationTable->SizeOfBlock);

		DWORD numOfitems = (pRelocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD item = (PWORD)((DWORD)pRelocationTable + sizeof(IMAGE_BASE_RELOCATION));

		//遍历所有块
		for (DWORD i = 0; i < numOfitems; i++)
		{
			WORD entry = item[i];
			DWORD offset = entry & 0xFFF;
			DWORD type = entry >> 12;
			DWORD fixupAddress = pRelocationTable->VirtualAddress + offset;
			printf("第%d项： 地址：%x 属性：%x\n", i + 1, fixupAddress, type);
		}
		printf("********************************************************\n");

		//跳到下一个块
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	free(pFileBuffer);
	pFileBuffer = nullptr;
}

void moveExportTable()
{
	void* pFileBuffer = nullptr;

	//读取文件到缓冲内存空间
	DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件到缓冲内存空间失败！\n");
		return ;
	}

	//解析PE头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}
	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//新增一个节
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	if (pOptionalHeader->SizeOfHeaders - ((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("空闲空间不够，无法添加节表！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	void* pNewFileBuffer = malloc(fileSize + 0x1000);
	if (pNewFileBuffer == nullptr)
	{
		printf("申请内存空间失败！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//增加节数和镜像大小
	pPEHeader->NumberOfSections += 1;
	pOptionalHeader->SizeOfImage += 0x1000;

	memset(pNewFileBuffer, 0, fileSize + 0x1000);
	memcpy(pNewFileBuffer, pFileBuffer, fileSize);

	//重新获取各个头部指针
	pDosHeader = (PIMAGE_DOS_HEADER)pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 2;
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;

	//初始化新节头
	memcpy(pNewSectionHeader, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	memset((void*)((DWORD)pNewSectionHeader + IMAGE_SIZEOF_SECTION_HEADER), 0, IMAGE_SIZEOF_SECTION_HEADER);

	strncpy((char*)pNewSectionHeader->Name, ".newsec", IMAGE_SIZEOF_SHORT_NAME);
	pNewSectionHeader->Misc.VirtualSize = 0x1000;
	pNewSectionHeader->VirtualAddress = pLastSectionHeader->VirtualAddress + (DWORD)Align(max(pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->SizeOfRawData), pOptionalHeader->SectionAlignment);
	pNewSectionHeader->SizeOfRawData = 0x1000;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

	DWORD newSectionFOA = pNewSectionHeader->PointerToRawData; //新增节的FOA
	DWORD newSectionFileAddr = (DWORD)pNewFileBuffer + newSectionFOA; //新增节的绝对地址

	//开始移动导出表
	DWORD exportTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportTableFOA = RvaToFileOffset(pNewFileBuffer, exportTableRVA);
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pNewFileBuffer + exportTableFOA);
	//1、移动AddressOfFunctions
	DWORD funcAddrTableFOA = RvaToFileOffset(pNewFileBuffer, pExportTable->AddressOfFunctions);
	DWORD funcAddrTableAddr = (DWORD)pNewFileBuffer + funcAddrTableFOA;
	memcpy((void*)newSectionFileAddr, (void*)funcAddrTableAddr, (4 * (pExportTable->NumberOfFunctions)));
	//2、移动AddressOfNameOrdinals
	DWORD funcOrdinalsTableFOA = RvaToFileOffset(pNewFileBuffer, pExportTable->AddressOfNameOrdinals);
	DWORD funcOrdinalsTableAddr = (DWORD)pNewFileBuffer + funcOrdinalsTableFOA;
	memcpy((void*)(newSectionFileAddr + (4 * (pExportTable->NumberOfFunctions))), (void*)funcOrdinalsTableAddr, (2 * (pExportTable->NumberOfNames)));
	//3、移动AddressOfNames
	DWORD funcNameTableFOA = RvaToFileOffset(pNewFileBuffer, pExportTable->AddressOfNames);
	DWORD funcNameTableAddr = (DWORD)pNewFileBuffer + funcNameTableFOA;
	memcpy((void*)(newSectionFileAddr + (4 * (pExportTable->NumberOfFunctions)) + (2 * (pExportTable->NumberOfNames))), (void*)funcNameTableAddr, (4 * (pExportTable->NumberOfNames)));
	//4、移动所有的函数名并修复AddressOfNames
	DWORD newFuncName = (newSectionFileAddr + (4 * (pExportTable->NumberOfFunctions)) + (6 * (pExportTable->NumberOfNames)));
	for (DWORD i = 0; i < pExportTable->NumberOfNames; i++)
	{
		DWORD funcNameRVA = ((PDWORD)funcNameTableAddr)[i];
		DWORD funcNameFOA = RvaToFileOffset(pNewFileBuffer, funcNameRVA);
		char* funcName = (char*)((DWORD)pNewFileBuffer + funcNameFOA);
		size_t funcNameLen = strlen(funcName) + 1;
		memcpy((void*)newFuncName , funcName, funcNameLen);

		((PDWORD)funcNameTableAddr)[i] = newFuncName - (DWORD)pNewFileBuffer - pNewSectionHeader->PointerToRawData + pNewSectionHeader->VirtualAddress;
		newFuncName += funcNameLen;
	}
	//5、复制IMAGE_EXPORT_DIRECTORY结构
	memcpy((void*)newFuncName, pExportTable, sizeof(IMAGE_EXPORT_DIRECTORY));
	//6、修复IMAGE_EXPORT_DIRECTORY结构中的AddressOfFunctions、AddressOfNameOrdinals、AddressOfNames
	PIMAGE_EXPORT_DIRECTORY pNewExportTable = (PIMAGE_EXPORT_DIRECTORY)newFuncName;
	pNewExportTable->AddressOfFunctions = pNewSectionHeader->VirtualAddress;
	pNewExportTable->AddressOfNameOrdinals = pNewSectionHeader->VirtualAddress + (4 * pExportTable->NumberOfFunctions);
	pNewExportTable->AddressOfNames = pNewSectionHeader->VirtualAddress + (4 * pExportTable->NumberOfFunctions) + (2 * pExportTable->NumberOfNames);
	//7、修复目录项中的值，指向新的IMAGE_EXPORT_DIRECTORY
	pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (DWORD)pNewExportTable - (DWORD)pNewFileBuffer - pNewSectionHeader->PointerToRawData + pNewSectionHeader->VirtualAddress;


	//存盘
	BOOL isOK = FALSE;
	isOK = MemoryTOFile(pNewFileBuffer, fileSize + 0x1000, FILEPATH_OUT_DLL);
	if (isOK)
	{
		printf("存盘成功！\n");
	}
	else
	{
		printf("存盘失败！\n");
	}

	//释放申请的内存并将指针置空
	free(pFileBuffer);
	free(pNewFileBuffer);
	pFileBuffer = nullptr;
	pNewFileBuffer = nullptr;
}

void moveRelocationTable()
{
	void* pFileBuffer = nullptr;

	//读取文件到缓冲内存空间
	DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件到缓冲内存空间失败！\n");
		return;
	}
	
	//解析PE头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}
	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//新增一个节
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	if (pOptionalHeader->SizeOfHeaders - ((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("空闲空间不够，无法添加节表！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	void* pNewFileBuffer = malloc(fileSize + 0x1000);
	if (pNewFileBuffer == nullptr)
	{
		printf("申请内存空间失败！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	//增加节数和镜像大小
	pPEHeader->NumberOfSections += 1;
	pOptionalHeader->SizeOfImage += 0x1000;

	memset(pNewFileBuffer, 0, fileSize + 0x1000);
	memcpy(pNewFileBuffer, pFileBuffer, fileSize);

	//重新获取各个头部指针
	pDosHeader = (PIMAGE_DOS_HEADER)pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 2;
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;

	//初始化新节头
	memcpy(pNewSectionHeader, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	memset((void*)((DWORD)pNewSectionHeader + IMAGE_SIZEOF_SECTION_HEADER), 0, IMAGE_SIZEOF_SECTION_HEADER);

	strncpy((char*)pNewSectionHeader->Name, ".newsec", IMAGE_SIZEOF_SHORT_NAME);
	pNewSectionHeader->Misc.VirtualSize = 0x1000;
	pNewSectionHeader->VirtualAddress = pLastSectionHeader->VirtualAddress + (DWORD)Align(max(pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->SizeOfRawData), pOptionalHeader->SectionAlignment);
	pNewSectionHeader->SizeOfRawData = 0x1000;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

	DWORD newSectionFOA = pNewSectionHeader->PointerToRawData; //新增节的FOA
	DWORD newSectionFileAddr = (DWORD)pNewFileBuffer + newSectionFOA; //新增节的绝对地址

	
	printf("oldImageBase:%x\n", pOptionalHeader->ImageBase);
	pOptionalHeader->ImageBase += 0x1000;
	printf("newImageBase:%x\n", pOptionalHeader->ImageBase);
	
	//开始移动重定位表
	DWORD pRelocationTableRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD pRelocationTableFOA = RvaToFileOffset(pNewFileBuffer, pRelocationTableRVA);
	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pNewFileBuffer + pRelocationTableFOA);

	//计算重定位表的大小
	DWORD sizeOfRelocationTable = 0;
	while (pRelocationTable->VirtualAddress != 0 && pRelocationTable->SizeOfBlock != 0)
	{
		
		sizeOfRelocationTable += pRelocationTable->SizeOfBlock;
		
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pNewFileBuffer + pRelocationTableFOA);
	//移动重定位表到新增节
	memcpy((void*)newSectionFileAddr, pRelocationTable, sizeOfRelocationTable);
	
	//修复重定位表（因为pOptionalHeader->ImageBase += 0x1000;）
	PIMAGE_BASE_RELOCATION pNewRelocationTable = (PIMAGE_BASE_RELOCATION)newSectionFileAddr;
	while (pNewRelocationTable->VirtualAddress != 0 && pNewRelocationTable->SizeOfBlock != 0)
	{
		pNewRelocationTable->VirtualAddress += 0x1000;

		//跳到下一个块
		pNewRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pNewRelocationTable + pNewRelocationTable->SizeOfBlock);
	}

	//修复目录项中的重定位表的地址
	pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = pNewSectionHeader->VirtualAddress;
	
	//存盘
	BOOL isOK = FALSE;
	isOK = MemoryTOFile(pNewFileBuffer, fileSize + 0x1000, FILEPATH_OUT_DLL);
	if (isOK)
	{
		printf("存盘成功！\n");
	}
	else
	{
		printf("存盘失败！\n");
	}

	//释放申请的内存并将指针置空
	free(pFileBuffer);
	free(pNewFileBuffer);
	pFileBuffer = nullptr;
	pNewFileBuffer = nullptr;
}

BOOL IsAllZero(BYTE* data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		if (data[i] != 0) {
			return FALSE;
		}
	}
	return TRUE;
}

void TestPrintImportTable()
{
	void* pFileBuffer = nullptr;

	//读取文件到缓冲内存空间
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if(fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件到缓冲内存空间失败！\n");
		return ;
	}

	//解析PE头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;

	//找到导入表地址
	DWORD importTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importTableFOA = RvaToFileOffset(pFileBuffer, importTableRVA);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + importTableFOA);
	
	while (pImportTable->OriginalFirstThunk != 0 && pImportTable->FirstThunk != 0)
	{
		//输出dll的名字
		DWORD dllNameRVA = pImportTable->Name;
		DWORD dllNameFOA = RvaToFileOffset(pFileBuffer, dllNameRVA);
		char* dllName = (char*)((DWORD)pFileBuffer + dllNameFOA);
		printf("*****************************************************\n");
		printf("%s\n", dllName);

		//遍历OriginalFirstThunk
		DWORD originalFirstThunkRVA = pImportTable->OriginalFirstThunk;
		DWORD originalFirstThunkFOA = RvaToFileOffset(pFileBuffer, originalFirstThunkRVA);
		PDWORD INTTable = (PDWORD)((DWORD)pFileBuffer + originalFirstThunkFOA);
		printf("-----------------------------------------------------\n");
		printf("-------------------OriginalFirstThunk---------------------\n");
		for (int i = 0;; i++)
		{
			if (INTTable[i] != 0)
			{
				if ((INTTable[i] & IMAGE_ORDINAL_FLAG) == IMAGE_ORDINAL_FLAG)
				{
					printf("按照序号导出：%Xh\n", (INTTable[i] & 0x7FFFFFFF));
				}
				else
				{
					DWORD INT_nameImportTableFOA = RvaToFileOffset(pFileBuffer, INTTable[i]);
					PIMAGE_IMPORT_BY_NAME pNameImportTable = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + INT_nameImportTableFOA);
					printf("按照名字导出：Hint-Name:%X-%s\n",pNameImportTable->Hint,pNameImportTable->Name);
				}
			}
			else
			{
				break;
			}
		}
		printf("-----------------------------------------------------\n");
		

		//遍历FirstThunk
		DWORD firstThunkRVA = pImportTable->FirstThunk;
		DWORD firstThunkFOA = RvaToFileOffset(pFileBuffer, firstThunkRVA);
		PDWORD IATTable = (PDWORD)((DWORD)pFileBuffer + firstThunkFOA);
		printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
		printf("+++++++++++++++++++++++++FirstThunk++++++++++++++++++++++++\n");
		for (int j = 0;; j++)
		{
			if (IATTable[j] != 0)
			{
				if ((IATTable[j] & 0x80000000) == 0x80000000)
				{
					printf("按照序号导出：%Xh\n", (IATTable[j] & 0x7FFFFFFF));
				}
				else
				{
					DWORD IAT_nameImportTableFOA = RvaToFileOffset(pFileBuffer, IATTable[j]);
					PIMAGE_IMPORT_BY_NAME pNameImportTable = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + IAT_nameImportTableFOA);
					printf("按照名字导出：Hint-Name:%X-%s\n", pNameImportTable->Hint, pNameImportTable->Name);
				}
			}
			else
			{
				break;
			}
		}
		
		pImportTable++;
	}
}


void TestPrintBoundImportTable()
{
	void* pFileBuffer = nullptr;

	//读取文件到缓冲内存空间
	DWORD fileSize = ReadPEFile(FILEPATH, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件到缓冲内存空间失败！\n");
		return ;
	}

	//解析PE头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
	}

	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;


	//找到绑定导入表
	DWORD boundImportTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
	printf("%x\n", boundImportTableRVA);
	DWORD boundImportTableFOA = RvaToFileOffset(pFileBuffer, boundImportTableRVA);
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportTable = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + boundImportTableFOA);


	//输出绑定导入表的所有信息
	printf("*********************IMAGE_BOUND_IMPORT_DESCRIPTOR***************************\n");
	printf("TimeDateStamp:%X\n", pBoundImportTable->TimeDateStamp);
	char* dllName = (char*)((DWORD)pFileBuffer + pBoundImportTable->OffsetModuleName);
	printf("dllName:%s\n", dllName);
	printf("NumberOfModuleForwarderRefs:%d\n", pBoundImportTable->NumberOfModuleForwarderRefs);
	PIMAGE_BOUND_FORWARDER_REF refTable = (PIMAGE_BOUND_FORWARDER_REF)((DWORD)pBoundImportTable + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
	while (IsAllZero((PBYTE)pBoundImportTable, sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR)) == FALSE)
	{
		for (int i = 0; i < pBoundImportTable->NumberOfModuleForwarderRefs; i++)
		{
			printf("*********************IMAGE_BOUND_FORWARDER_REF***************************\n");
			printf("TimeDateStamp:%X\n", refTable->TimeDateStamp);
			char* dllName1 = (char*)((DWORD)pFileBuffer + refTable->OffsetModuleName);
			printf("dllName:%s\n", dllName1);
		}
	}

	//释放内存
	free(pFileBuffer);
	pFileBuffer = nullptr;
}


void injectByImportTable()
{
	void* pFileBuffer = nullptr;

	//读取文件到缓冲内存空间
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("读取文件到缓冲内存空间失败！\n");
		return ;
	}

	//解析PE头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("无效的DOS头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("无效的PE头！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//新增一个节
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	if (pOptionalHeader->SizeOfHeaders - ((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("空闲空间不够，无法添加节表！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	DWORD newFileSize = fileSize + 0x500;
	void* pNewFileBuffer = malloc(newFileSize);
	if (pNewFileBuffer == nullptr)
	{
		printf("申请内存空间失败！\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	//增加节数和镜像大小
	pPEHeader->NumberOfSections += 1;
	pOptionalHeader->SizeOfImage += 0x500;

	memset(pNewFileBuffer, 0, newFileSize);
	memcpy(pNewFileBuffer, pFileBuffer, fileSize);

	//重新获取各个头部指针
	pDosHeader = (PIMAGE_DOS_HEADER)pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 2;
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;

	//初始化新节表
	memcpy(pNewSectionHeader, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	memset((void*)((DWORD)pNewSectionHeader + IMAGE_SIZEOF_SECTION_HEADER), 0, IMAGE_SIZEOF_SECTION_HEADER);
	//修改新节表属性
	strncpy((char*)pNewSectionHeader->Name, ".newsec", IMAGE_SIZEOF_SHORT_NAME);
	pNewSectionHeader->Misc.VirtualSize = 0x500;
	pNewSectionHeader->VirtualAddress = pLastSectionHeader->VirtualAddress + (DWORD)Align(max(pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->SizeOfRawData), pOptionalHeader->SectionAlignment);
	pNewSectionHeader->SizeOfRawData = 0x500;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	pNewSectionHeader->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	pNewSectionHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;
	pNewSectionHeader->Characteristics |= IMAGE_SCN_MEM_READ;

	DWORD newSectionFOA = pNewSectionHeader->PointerToRawData; //新增节的FOA
	DWORD newSectionFileAddr = (DWORD)pNewFileBuffer + newSectionFOA; //新增节的绝对地址

	//移动原导入表
	DWORD importTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importTableFOA = RvaToFileOffset(pNewFileBuffer, importTableRVA);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pNewFileBuffer + importTableFOA);
	DWORD sizeOfImportTable = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	// 复制导入表到新节，并清空新节的剩余部分
	memcpy((void*)newSectionFileAddr, pImportTable, sizeOfImportTable);
	memset((void*)((DWORD)newSectionFileAddr + sizeOfImportTable), 0, 0x500 - sizeOfImportTable);

	
	//添加导入表
	PIMAGE_IMPORT_DESCRIPTOR pNewImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)newSectionFileAddr + sizeOfImportTable - sizeof(IMAGE_IMPORT_DESCRIPTOR));
	memset((void*)((DWORD)pNewImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR)), 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	//添加INT表和IAT表
	PIMAGE_THUNK_DATA32 INTTable = (PIMAGE_THUNK_DATA32)((DWORD)pNewImportTable + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR));
	PIMAGE_THUNK_DATA32 IATTable = (PIMAGE_THUNK_DATA32)((DWORD)INTTable + 0x8);
	pNewImportTable->OriginalFirstThunk = (DWORD)INTTable - (DWORD)pNewFileBuffer - newSectionFOA + pNewSectionHeader->VirtualAddress;
	pNewImportTable->FirstThunk = (DWORD)IATTable - (DWORD)pNewFileBuffer - newSectionFOA + pNewSectionHeader->VirtualAddress;
	//添加IMAGE_IMPORT_BY_NAME
	PIMAGE_IMPORT_BY_NAME importByNameTable = (PIMAGE_IMPORT_BY_NAME)((DWORD)IATTable + 0x8);
	char funcName[] = "ExportFunction";
	strncpy((char*)importByNameTable->Name, funcName, sizeof(funcName));
	importByNameTable->Hint = 0;

	INTTable->u1.AddressOfData = ((DWORD)importByNameTable - (DWORD)pNewFileBuffer - newSectionFOA + pNewSectionHeader->VirtualAddress) & 0x7FFFFFFF;
	IATTable->u1.AddressOfData = ((DWORD)importByNameTable - (DWORD)pNewFileBuffer - newSectionFOA + pNewSectionHeader->VirtualAddress) & 0x7FFFFFFF;

	//存储dll名称
	char dllName[] = "InjectDll.dll";
	DWORD dllNameFileAddr = (DWORD)importByNameTable + sizeof(PIMAGE_IMPORT_BY_NAME) + sizeof(funcName) - 1;
	strncpy((char*)dllNameFileAddr, dllName, sizeof(dllName) + 1);

	//修正新增导入表的Name属性
	DWORD dllNameRVA = dllNameFileAddr - (DWORD)pNewFileBuffer - pNewSectionHeader->PointerToRawData + pNewSectionHeader->VirtualAddress;
	pNewImportTable->Name = dllNameRVA;


	//修正IMAGE_DATA_DIRECTORY结构的VirtualAddress和Size
	pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pNewSectionHeader->VirtualAddress;
	DWORD newSizeOfImportTable = sizeOfImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR);
	pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = newSizeOfImportTable;

	
	

	//存盘
	BOOL isOK = FALSE;
	isOK = MemoryTOFile(pNewFileBuffer, newFileSize, FILEPATH_OUT);
	if (isOK)
	{
		printf("存盘成功！\n");
	}
	else
	{
		printf("存盘失败！\n");
	}

	//释放内存
	free(pFileBuffer);
	free(pNewFileBuffer);
	pFileBuffer = nullptr;
	pNewFileBuffer = nullptr;
}