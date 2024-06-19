//Global.cpp
#include "Global.h"
#include <stdio.h>
#include <stdlib.h>

#define FILEPATH_IN "E:\\����\\fg.exe"
#define FILEPATH_IN_DLL "E:\\����\\Mydll.dll"
#define FILEPATH_OUT "E:\\����\\fg_new.exe"
#define FILEPATH_OUT_DLL "E:\\����\\Mydll_new.dll"
#define FILEPATH "E:\\����\\injectDll.dll"
#define SHELLCODELEN 0x12
#define MESSAGEBOXADDR 0x76A4A740

//ȫ�ֱ���
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
		printf("��Ч�����������\n");
		return 0;
	}

	//���ļ�
	FILE* pFile = fopen(lpszFile, "rb");
	if (pFile == nullptr)
	{
		printf("�޷����ļ���%s\n",lpszFile);
		return 0;
	}

	//��ȡ�ļ���С
	fseek(pFile, 0, SEEK_END);
	DWORD fileSize = ftell(pFile);
	rewind(pFile);

	//�����ڴ�ռ�
	void* pTempFileBuffer = malloc(fileSize);
	if (pTempFileBuffer == nullptr)
	{
		printf("�����ڴ�ʧ�ܣ�\n");
		fclose(pFile);
		return 0;
	}

	//��ʼ���ڴ�ռ�
	memset(pTempFileBuffer, 0, fileSize);

	//���ļ����ݶ�ȡ��������
	size_t bytesRead = fread(pTempFileBuffer, 1, fileSize, pFile);
	if (bytesRead != fileSize)
	{
		printf("��ȡ�ļ�����ʧ�ܣ�\n");
		free(pTempFileBuffer);
		fclose(pFile);
		return 0;
	}

	//�ر��ļ�
	*pFileBuffer = pTempFileBuffer;
	fclose(pFile);

	return fileSize;
}

void TestPrintPEHeader(const char* lpszFile)
{
	if (lpszFile == nullptr)
	{
		printf("��Ч�����������\n");
	}

	void* pFileBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOSͷ										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NTͷ(������׼PEͷ�Ϳ�ѡPEͷ)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //��׼PEͷ										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //��ѡPEͷ										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //�ڱ�	


	DWORD fileSize = ReadPEFile(lpszFile, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("��ȡ�ļ�ʧ�ܣ�\n");
		return ;
	}

	//�ж�MZ��־
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//�ж�PE��־
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//��ӡPEͷ��Ϣ
	printf("***************************DOSͷ***************************\n");
	printf("e_magic:%x\n", pDosHeader->e_magic);
	printf("e_lfanew:%x\n", pDosHeader->e_lfanew);

	printf("***************************PEͷ��־***************************\n");
	printf("PE��־��%x\n", pNTHeader->Signature);

	printf("***************************��׼PEͷ***************************\n");
	printf("Machine:%x\n", pPEHeader->Machine);
	printf("�ڵ�����:%x\n", pPEHeader->NumberOfSections);
	printf("��ѡPEͷ�Ĵ�С:%x\n", pPEHeader->SizeOfOptionalHeader);

	printf("***************************��ѡPEͷ***************************\n");
	printf("������ڵ�ƫ��:%x\n", pOptionalHeader->AddressOfEntryPoint);
	printf("�ڴ����:%x\n", pOptionalHeader->SectionAlignment);
	printf("�ļ�����:%x\n", pOptionalHeader->FileAlignment);
	printf("SizeOfHeaders:%x\n", pOptionalHeader->SizeOfHeaders);

	printf("***************************�ڱ�***************************\n");
	for (int i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeader++)
	{
		printf("�����ƣ�%s\n", pSectionHeader->Name);
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
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOSͷ										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NTͷ(������׼PEͷ�Ϳ�ѡPEͷ)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //��׼PEͷ										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //��ѡPEͷ										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //�ڱ�	

	
	if (pFileBuffer == nullptr)
	{
		printf("������ָ����Ч��\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־��\n");
		return 0;
	}
	//�ж��Ƿ�����Ч��PE��־
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־��\n");
		return 0;
	}
	pPEHeader = &pNTHeader->FileHeader;
	//��ѡPEͷ
	pOptionalHeader = &pNTHeader->OptionalHeader;
	//��һ���ڱ��ָ��
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//����SizeOfImage�����ڴ�ռ�
	pTempImageBuffer = malloc(pOptionalHeader->SizeOfImage);
	if (pTempImageBuffer == nullptr)
	{
		printf("���仺�����ڴ�ռ�ʧ�ܣ�\n");
		return 0;
	}

	//��ʼ��������
	memset(pTempImageBuffer, 0, pOptionalHeader->SizeOfImage);

	//��FileBuffer�е�PEͷ���Ƶ�ImageBuffer
	memcpy(pTempImageBuffer, pDosHeader, pOptionalHeader->SizeOfHeaders);

	//��FileBuffer�еĸ����ڸ��Ƶ�ImageBuffer
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++, pTempSectionHeader++)
	{
		memcpy((void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress),
			   (void*)((DWORD)pDosHeader + pTempSectionHeader->PointerToRawData),
			   max(pTempSectionHeader->SizeOfRawData, pTempSectionHeader->Misc.VirtualSize));
	}

	//��������
	*pImageBuffer = pTempImageBuffer;
	return pOptionalHeader->SizeOfImage;
}


DWORD CopyImageBufferToNewBuffer(IN const void* pImageBuffer, OUT void** pNewBuffer)
{
	void* pTempNewBuffer = nullptr;
	DWORD newSize = 0;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOSͷ										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NTͷ(������׼PEͷ�Ϳ�ѡPEͷ)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //��׼PEͷ										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //��ѡPEͷ										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //�ڱ�	


	if (pImageBuffer == nullptr)
	{
		printf("������ָ����Ч��\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־");
		return 0;
	}
	//�ж��Ƿ�����Ч��PE��־
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־��\n");
		return 0;
	}
	pPEHeader = &pNTHeader->FileHeader;
	//��ѡPEͷ
	pOptionalHeader = &pNTHeader->OptionalHeader;
	//��һ���ڱ��ָ��
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//ImageBuffer�����һ���ڵĿ�ʼ�����һ���ڵĴ�С
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	newSize = (pLastSectionHeader->PointerToRawData) + (pLastSectionHeader->SizeOfRawData);

	//���仺�����ڴ�ռ�
	pTempNewBuffer = malloc(newSize);
	if (pTempNewBuffer == nullptr)
	{
		printf("���仺�����ռ�ʧ�ܣ�\n");
		return 0;
	}

	//��ʼ��������
	memset(pTempNewBuffer, 0, newSize);

	//��ImageBuffer�е�PEͷ���Ƶ�NewBuffer
	memcpy(pTempNewBuffer, pImageBuffer, pOptionalHeader->SizeOfHeaders);

	//�������ڰ��ļ�����ķ�ʽ��ImageBuffer�е�PEͷ���Ƶ�NewBuffer
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++, pTempSectionHeader++)
	{
		memcpy((void*)((DWORD)pTempNewBuffer + pTempSectionHeader->PointerToRawData),
			   (void*)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress),
			   max(pTempSectionHeader->SizeOfRawData, pTempSectionHeader->Misc.VirtualSize));
	}

	//��������
	*pNewBuffer = pTempNewBuffer;
	return newSize;
}

BOOL MemoryTOFile(IN const void* pMemBuffer, IN size_t size, OUT const char* lpszFile)
{
	if (pMemBuffer == nullptr || size == 0)
	{
		printf("��Ч�����������\n");
		return 0;
	}

	FILE* pFile = fopen(lpszFile, "wb");
	if (pFile == nullptr)
	{
		return 0;
	}

	//������д���ļ�
	size_t written = fwrite(pMemBuffer, 1, size, pFile);

	//���д���Ƿ�ɹ�
	if (written != size)
	{
		printf("д������ʱ��������\n");
		fclose(pFile);
		return FALSE;
	}

	fclose(pFile);

	return written;
}

DWORD RvaToFileOffset(IN const void* pFileBuffer, IN DWORD dwRva)
{
	//����������
	if (pFileBuffer == nullptr || dwRva == 0)
	{
		printf("��Ч�����������\n");
		return 0;
	}

	//����DOSͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		return 0;
	}

	//����NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		return 0;
	}

	//��ȡ�ڱ�
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)&pNTHeader->OptionalHeader + pNTHeader->FileHeader.SizeOfOptionalHeader);
	
	//�������нڣ��ҵ�Rva���ڽ�
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
		printf("û���ҵ���Ӧ�Ľڣ�\n");
		return 0;
	}

	//��ַת��
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
		printf("��ȡ�ļ�ʧ�ܣ�\n");
		return ;
	}

	DWORD filebufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (filebufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBufferʧ�ܣ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	DWORD size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || pNewBuffer == nullptr)
	{
		printf("ImageBuffer--->NewBufferʧ�ܣ�\n");
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
		printf("���̳ɹ���\n");
	}
	else
	{
		printf("����ʧ�ܣ�\n");
	}

	recycleMemory(&pFileBuffer, &pImageBuffer, &pNewBuffer);
}

void TestAddCodeInCodeSec()
{
	void* pFileBuffer = nullptr;
	void* pImageBuffer = nullptr;
	void* pNewBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOSͷ										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NTͷ(������׼PEͷ�Ϳ�ѡPEͷ)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //��׼PEͷ										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //��ѡPEͷ										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //�ڱ�	
	PBYTE codeBegin = nullptr;
	BOOL isOK = FALSE;
	DWORD size = 0;

	//File--->FileBuffer
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("�ļ�--->������ʧ�ܣ�\n");
		return ;
	}

	//FileBuffer--->ImageBuffer
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBufferʧ�ܣ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//�жϴ���ο������Ƿ��㹻�洢ShellCode����
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	if ((pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize) < SHELLCODELEN)
	{
		printf("������пռ䲻��");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}

	//�����븴�Ƶ�������
	codeBegin = (PBYTE)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	memcpy(codeBegin, shellcode, SHELLCODELEN);
	
	//����E8
	DWORD callAddr = MESSAGEBOXADDR - (pOptionalHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)(pImageBuffer)));
	*(PDWORD)(codeBegin + 9) = callAddr;

	//����E9
	DWORD jmpAddr = (pOptionalHeader->ImageBase + pOptionalHeader->AddressOfEntryPoint) - (pOptionalHeader->ImageBase + ((DWORD)(codeBegin + SHELLCODELEN) - (DWORD)(pImageBuffer)));
	*(PDWORD)(codeBegin + 0xE) = jmpAddr;
	
	//�޸�OEP
	pOptionalHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pImageBuffer;

	//ImageBuffer--->NewBuffer
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || pNewBuffer == nullptr)
	{
		printf("ImageBuffer--->NewBufferʧ�ܣ�\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}
	//NewBuffer--->�ļ�
	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if (isOK)
	{
		printf("���̳ɹ���\n");
	}
	else
	{
		printf("����ʧ�ܣ�\n");
	}

	//�ͷ��ڴ�
	recycleMemory(&pFileBuffer, &pImageBuffer, &pNewBuffer);
}

void TestAddCodeInDataSec(WORD sectionIndex)
{
	void* pFileBuffer = nullptr;
	void* pImageBuffer = nullptr;
	void* pNewBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOSͷ										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NTͷ(������׼PEͷ�Ϳ�ѡPEͷ)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //��׼PEͷ										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //��ѡPEͷ										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //�ڱ�	
	PBYTE codeBegin = nullptr;
	BOOL isOK = FALSE;
	DWORD size = 0;

	//File--->FileBuffer
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("�ļ�--->������ʧ�ܣ�\n");
		return ;
	}

	//FileBuffer--->ImageBuffer
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBufferʧ�ܣ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//�жϴ���ο������Ƿ��㹻�洢ShellCode����
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	if (sectionIndex > pPEHeader->NumberOfSections)
	{
		printf("û�д˽ڣ�\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}
	PIMAGE_SECTION_HEADER pSectionHeaderX = pSectionHeader + (sectionIndex - 1); //��section���ڵĽڱ�λ��
	if ((pSectionHeaderX->SizeOfRawData - pSectionHeaderX->Misc.VirtualSize) < SHELLCODELEN)
	{
		printf("�˽ڿ��пռ䲻�㣡\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}
	
	//��shellcode���븴�Ƶ��˽ڵĿ�����
	codeBegin = (PBYTE)((DWORD)(pImageBuffer) + pSectionHeaderX->VirtualAddress + pSectionHeaderX->Misc.VirtualSize);
	memcpy(codeBegin, shellcode, SHELLCODELEN);

	//����E8
	DWORD callAddr = MESSAGEBOXADDR - (pOptionalHeader->ImageBase + (DWORD)(codeBegin + 0xD) - (DWORD)(pImageBuffer));
	*((PDWORD)(codeBegin + 0x9)) = callAddr;
	
	//����E9
	DWORD jmpAddr = (pOptionalHeader->ImageBase + pOptionalHeader->AddressOfEntryPoint) - (pOptionalHeader->ImageBase + (DWORD)(codeBegin + SHELLCODELEN) - (DWORD)(pImageBuffer));
	*((PDWORD)(codeBegin + 0xE)) = jmpAddr;

	//�޸�OEP
	pOptionalHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pImageBuffer;

	//��ӿ�ִ��Ȩ��
	pSectionHeaderX->Characteristics |= IMAGE_SCN_MEM_EXECUTE;


	//ImageBuffer--->NewBuffer
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if(!size || pNewBuffer == nullptr)
	{
		printf("ImageBuffer--->NewBufferʧ�ܣ�\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}

	//NewBuffer--->�ļ�
	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if (isOK)
	{
		printf("���̳ɹ���\n");
	}

	//�ͷ��ڴ�
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
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOSͷ										
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NTͷ(������׼PEͷ�Ϳ�ѡPEͷ)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //��׼PEͷ										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //��ѡPEͷ										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //�ڱ�	
	PBYTE codeBegin = nullptr;
	BOOL isOK = FALSE;
	DWORD size = 0;

	//�ļ�--->������
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("�ļ�--->������ʧ�ܣ�\n");
		return ;
	}

	//FileBuffer--->ImageBuffer
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBufferʧ�ܣ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//�ж��Ƿ����㹻�Ŀռ����һ���ڱ�
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;
	PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);

	if (pOptionalHeader->SizeOfHeaders - ((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("���пռ䲻�����޷���ӽڱ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//����һ���ڵ�����
	pNewImageBuffer = malloc(_msize(pImageBuffer) + 0x1000);
	if (pNewImageBuffer == nullptr)
	{
		printf("�����ڴ�ռ�ʧ�ܣ�\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return;
	}

	//�ڵ�����+1
	pPEHeader->NumberOfSections += 1;

	//�ı�SizeOfImage
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

	//����һ���ڱ�(���Ƶ�һ���ڱ�)
	memcpy(pNewSectionHeader, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	//�������ڱ�������һ���ڱ��С��0
	memset((void*)((DWORD)pNewSectionHeader + IMAGE_SIZEOF_SECTION_HEADER), 0, IMAGE_SIZEOF_SECTION_HEADER);


	//�޸������ڱ������
	strncpy((char *)pNewSectionHeader->Name, ".newsec", IMAGE_SIZEOF_SHORT_NAME);
	pNewSectionHeader->Misc.VirtualSize = 0x1000;
	pNewSectionHeader->VirtualAddress = pLastSectionHeader->VirtualAddress + (DWORD)Align(max(pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->SizeOfRawData), pOptionalHeader->SectionAlignment);
	pNewSectionHeader->SizeOfRawData = 0x1000;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	/*
	//���������в���shellcode������E8 E9
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
		printf("NewImageBuffer--->NewBufferʧ�ܣ�\n");
		recycleMemory(&pFileBuffer, &pImageBuffer, &pNewImageBuffer);
		return ;
	}

	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if(isOK)
	{
		printf("���̳ɹ���\n");
	}

	//�ͷ��ڴ�
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
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOSͷ
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NTͷ(������׼PEͷ�Ϳ�ѡPEͷ)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //��׼PEͷ										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //��ѡPEͷ										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //�ڱ�	
	BOOL isOK = FALSE;
	DWORD size = 0;


	//�ļ�--->������
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("�ļ�--->������ʧ�ܣ�\n");
		return ;
	}

	//FileBuffer--->ImageBuffer
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBufferʧ�ܣ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//����PEͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);

	//�����µ��ڴ�
	newBuffer = malloc(pOptionalHeader->SizeOfImage + expSize);
	if (newBuffer == nullptr)
	{
		printf("�����ڴ�ռ�ʧ�ܣ�\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}
	memset(newBuffer, 0, pOptionalHeader->SizeOfImage + expSize);

	//�޸������֮��Ľڱ����Ժ�
	DWORD tempSize = (DWORD)Align(pLastSectionHeader->Misc.VirtualSize, pOptionalHeader->SectionAlignment) + expSize;
	pLastSectionHeader->SizeOfRawData = tempSize;
	pLastSectionHeader->Misc.VirtualSize = tempSize;
	pOptionalHeader->SizeOfImage += expSize;

	memcpy(newBuffer, pImageBuffer, pOptionalHeader->SizeOfImage - expSize);

	//newBuffer--->NewBuffer
	size = CopyImageBufferToNewBuffer(newBuffer, &pNewBuffer);
	if (size == 0 || pNewBuffer == nullptr)
	{
		printf("newBuffer--->NewBufferʧ�ܣ�\n");
		recycleMemory(&pFileBuffer, &pImageBuffer, &newBuffer);
		return ;
	}

	//����
	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if (isOK)
	{
		printf("���̳ɹ���\n");
	}

	//�ͷ��ڴ�
	recycleMemory(&pFileBuffer, &pImageBuffer, &newBuffer);
	free(pNewBuffer);
	pNewBuffer = nullptr;
}

void TestMergeSec()
{
	void* pFileBuffer = nullptr;
	void* pImageBuffer = nullptr;
	void* pNewBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOSͷ
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NTͷ(������׼PEͷ�Ϳ�ѡPEͷ)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //��׼PEͷ										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //��ѡPEͷ										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //�ڱ�	
	BOOL isOK = FALSE;
	DWORD size = 0;

	//�ļ�--->������
	DWORD fileSize =  ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("�ļ�--->������ʧ�ܣ�\n");
		return ;
	}

	//FileBuffer--->
	DWORD fileBufferSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (fileBufferSize == 0 || pImageBuffer == nullptr)
	{
		printf("FileBuffer--->ImageBufferʧ�ܣ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	// ����PEͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//�޸ĵ�һ���ڵ�����
	DWORD alignedSizeOfHeaders = Align(pOptionalHeader->SizeOfHeaders, pOptionalHeader->SectionAlignment);
	DWORD newSizeOfRawData = pOptionalHeader->SizeOfImage - alignedSizeOfHeaders;
	pSectionHeader->SizeOfRawData = newSizeOfRawData;
	pSectionHeader->Misc.VirtualSize = newSizeOfRawData;

	//�ڵ�������Ϊ1
	pPEHeader->NumberOfSections = 1;

	//�޸Ľ�Ȩ��
	pSectionHeader->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	pSectionHeader->Characteristics |= IMAGE_SCN_MEM_READ;
	pSectionHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;

	//ImageBuffer--->NewBuffer
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || pNewBuffer == NULL)
	{
		printf("ImageBuffer--->NewBufferʧ�ܣ�\n");
		free(pFileBuffer);
		free(pImageBuffer);
		pFileBuffer = nullptr;
		pImageBuffer = nullptr;
		return ;
	}

	//����
	isOK = MemoryTOFile(pNewBuffer, size, FILEPATH_OUT);
	if (isOK)
	{
		printf("���̳ɹ���\n");
	}
	else
	{
		printf("����ʧ�ܣ�\n");
	}

	//�ͷ��ڴ�
	recycleMemory(&pFileBuffer, &pImageBuffer, &pNewBuffer);
}

void TestPrintDirectory()
{
	void* pFileBuffer = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr; //DOSͷ
	PIMAGE_NT_HEADERS pNTHeader = nullptr;  //NTͷ(������׼PEͷ�Ϳ�ѡPEͷ)										
	PIMAGE_FILE_HEADER pPEHeader = nullptr; //��׼PEͷ										
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = nullptr; //��ѡPEͷ										
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr; //�ڱ�	

	DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("��ȡ�ļ�ʧ�ܣ�\n");
		return ;
	}

	pDosHeader = PIMAGE_DOS_HEADER(pFileBuffer);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч�ĵ�MZ��־��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ; 
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PE��־��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//��ӡĿ¼��
	printf("������VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	printf("�����VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	printf("��Դ��VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
	printf("�쳣��Ϣ��VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
	printf("��ȫ֤���VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
	printf("�ض�λ��VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	printf("������Ϣ��VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	printf("��Ȩ���б�VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
	printf("ȫ��ָ���VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
	printf("TLS��VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
	printf("�������ñ�VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
	printf("�󶨵����VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
	printf("IAT��VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
	printf("�ӳٵ����VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
	printf("COM��Ϣ��VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);
	printf("������VirtualAddress:%x��size:%x\n", pOptionalHeader->DataDirectory[15].VirtualAddress, pOptionalHeader->DataDirectory[15].Size);
	
	//�ͷ��ڴ�
	free(pFileBuffer);
	pFileBuffer = nullptr;
}

void TestPrintExportTable()
{
	void* pFileBuffer = nullptr;

	//��ȡ�ļ���������
	 DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("��ȡ�ļ�ʧ�ܣ�\n");
		return ;
	}

	//����DOSͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//����NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//��ȡ�������ַ
	DWORD exportTableVAddress = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportTableFAddress = RvaToFileOffset(pFileBuffer, exportTableVAddress);
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportTableFAddress);

	//��ӡ������������Ϣ
	printf("�����ֶ�(Characteristics):%x\n", pExportTable->Characteristics);
	printf("���������ɵ�ʱ���(TimeDateStamp):%x\n", pExportTable->TimeDateStamp);
	printf("����������汾��(MajorVersion):%x\n", pExportTable->MajorVersion);
	printf("������Ĵΰ汾��(MinorVersion):%x\n", pExportTable->MinorVersion);
	printf("------------------------------------------------------------------\n");

	DWORD fileOffsetOfName = RvaToFileOffset(pFileBuffer, pExportTable->Name);
	printf("ģ�����Ƶ�FOA(fileOffsetOfName):%x\n", fileOffsetOfName);
	printf("ģ�����Ƶ�RVA(Name):%x\n", pExportTable->Name);
	printf("ģ�����ƣ�%s\n", (char*)((DWORD)pFileBuffer + fileOffsetOfName));
	printf("������������ʼ���(Base):%x\n", pExportTable->Base);
	printf("��������������(NumberOfFunctions):%x\n", pExportTable->NumberOfFunctions);
	printf("�������Ƶ�����(NumberOfNames):%x\n", pExportTable->NumberOfNames);
	printf("------------------------------------------------------------------\n");

	DWORD fileOffsetOfFunctions = RvaToFileOffset(pFileBuffer, pExportTable->AddressOfFunctions);
	DWORD fileOffsetOfNames = RvaToFileOffset(pFileBuffer, pExportTable->AddressOfNames);
	DWORD fileOffsetOfNameOrdinals = RvaToFileOffset(pFileBuffer, pExportTable->AddressOfNameOrdinals);
	printf("����������ַ�������ʼ��ַ(RVA)(AddressOfFunctions):%x\n", pExportTable->AddressOfFunctions);
	printf("���������������ʼ��ַ(RVA)(AddressOfNames):%x\n", pExportTable->AddressOfNames);
	printf("������������������ʼ��ַ(RVA)(AddressOfNameOrdinals):%x\n", pExportTable->AddressOfNameOrdinals);
	printf("------------------------------------------------------------------\n");
	printf("����������ַ�������ʼ��ַ(FOA)(fileOffsetOfFunctions):%x\n", fileOffsetOfFunctions);
	printf("���������������ʼ��ַ(FOA)(fileOffsetOfNames):%x\n", fileOffsetOfNames);
	printf("������������������ʼ��ַ(FOA)(fileOffsetOfNameOrdinals):%x\n", fileOffsetOfNameOrdinals);

	// ��ȡ�������еĵ�ַ
	PDWORD addressOfNames = (PDWORD)((DWORD)pFileBuffer + fileOffsetOfNames);
	PWORD addressOfNameOrdinals = (PWORD)((DWORD)pFileBuffer + fileOffsetOfNameOrdinals);
	PDWORD addressOfFunctions = (PDWORD)((DWORD)pFileBuffer + fileOffsetOfFunctions);

	printf("------------------------------------------------------------------\n");
	// ��ӡ���е������������ơ���ַ�����
	for (DWORD i = 0; i < pExportTable->NumberOfNames; i++)
	{
		DWORD functionNameRVA = addressOfNames[i];
		DWORD functionNameFOA = RvaToFileOffset(pFileBuffer, functionNameRVA);
		char* funcName = (char*)((DWORD)pFileBuffer + functionNameFOA);
		WORD ordinal = addressOfNameOrdinals[i] + pExportTable->Base;
		DWORD functionRVA = addressOfFunctions[addressOfNameOrdinals[i]];
		DWORD functionFOA = RvaToFileOffset(pFileBuffer, functionRVA);
		printf("������: %s, �������: %d, ������ַ: %x\n", funcName, ordinal, functionFOA);
	}

	free(pFileBuffer);
	pFileBuffer = nullptr;
}

DWORD GetFunctionAddrByName(IN const void* pFileBuffer, IN const char* functionName)
{
	if (pFileBuffer == nullptr)
	{
		printf("������ָ����Ч��\n");
		return 0;
	}

	//����PEͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		return 0;
	}
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if(pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		return 0;
	}

	//�ҵ�������
	DWORD exportTableRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportTableFOA = RvaToFileOffset(pFileBuffer, exportTableRVA);
	if (exportTableFOA == 0)
	{
		printf("��Ч�ĵ����� RVA��\n");
		return 0;
	}
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportTableFOA);


	//���ݺ������ҳ�������ַ
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
		printf("��Ч�Ļ�����ָ�룡\n");
		return 0;
	}
	
	//����PEͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		return 0;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		return 0;
	}
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;

	//�ҳ�������
	DWORD exportTableRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportTableFOA = RvaToFileOffset(pFileBuffer, exportTableRVA);
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportTableFOA);

	//ȷ����������ڷ�Χ��
	if (ordinal < pExportTable->Base || ordinal >= pExportTable->Base + pExportTable->AddressOfFunctions)
	{
		printf("��Ч�ĵ�����ţ�\n");
		return 0;
	}

	//���ݵ�������ҳ�������ַ
	DWORD exportOrdinal = ordinal - pExportTable->Base;
	PDWORD addressOfNameOrdinals = (PDWORD)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportTable->AddressOfNameOrdinals));
	PDWORD addressOfFunction = (PDWORD)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportTable->AddressOfFunctions));

	DWORD funcRVA = addressOfFunction[exportOrdinal];

	return funcRVA;
}

void TestGetFunctionAddr()
{
	void* pFileBuffer = nullptr;

	//����dll�ļ�
	DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("����DLLʧ�ܣ�\n");
		return ; 
	}

	//��ȡ������ַ����ӡ
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
		printf("��ȡ�ļ�ʧ�ܣ�\n");
		return ;
	}

	//����PEͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ; 
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//�ҵ��ض�λ��
	DWORD relocationTableRVA =  pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD relocationTableFOA = RvaToFileOffset(pFileBuffer, relocationTableRVA);
	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + relocationTableFOA);


	//��ӡ�ض�λ��������Ϣ
	while (pRelocationTable->VirtualAddress != 0 && pRelocationTable->SizeOfBlock != 0)
	{
		printf("VirtualAddress:%x\n", pRelocationTable->VirtualAddress);
		printf("SizeOfBlock:%x\n", pRelocationTable->SizeOfBlock);

		DWORD numOfitems = (pRelocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD item = (PWORD)((DWORD)pRelocationTable + sizeof(IMAGE_BASE_RELOCATION));

		//�������п�
		for (DWORD i = 0; i < numOfitems; i++)
		{
			WORD entry = item[i];
			DWORD offset = entry & 0xFFF;
			DWORD type = entry >> 12;
			DWORD fixupAddress = pRelocationTable->VirtualAddress + offset;
			printf("��%d� ��ַ��%x ���ԣ�%x\n", i + 1, fixupAddress, type);
		}
		printf("********************************************************\n");

		//������һ����
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	free(pFileBuffer);
	pFileBuffer = nullptr;
}

void moveExportTable()
{
	void* pFileBuffer = nullptr;

	//��ȡ�ļ��������ڴ�ռ�
	DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("��ȡ�ļ��������ڴ�ռ�ʧ�ܣ�\n");
		return ;
	}

	//����PEͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}
	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//����һ����
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	if (pOptionalHeader->SizeOfHeaders - ((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("���пռ䲻�����޷���ӽڱ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	void* pNewFileBuffer = malloc(fileSize + 0x1000);
	if (pNewFileBuffer == nullptr)
	{
		printf("�����ڴ�ռ�ʧ�ܣ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	//���ӽ����;����С
	pPEHeader->NumberOfSections += 1;
	pOptionalHeader->SizeOfImage += 0x1000;

	memset(pNewFileBuffer, 0, fileSize + 0x1000);
	memcpy(pNewFileBuffer, pFileBuffer, fileSize);

	//���»�ȡ����ͷ��ָ��
	pDosHeader = (PIMAGE_DOS_HEADER)pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 2;
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;

	//��ʼ���½�ͷ
	memcpy(pNewSectionHeader, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	memset((void*)((DWORD)pNewSectionHeader + IMAGE_SIZEOF_SECTION_HEADER), 0, IMAGE_SIZEOF_SECTION_HEADER);

	strncpy((char*)pNewSectionHeader->Name, ".newsec", IMAGE_SIZEOF_SHORT_NAME);
	pNewSectionHeader->Misc.VirtualSize = 0x1000;
	pNewSectionHeader->VirtualAddress = pLastSectionHeader->VirtualAddress + (DWORD)Align(max(pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->SizeOfRawData), pOptionalHeader->SectionAlignment);
	pNewSectionHeader->SizeOfRawData = 0x1000;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

	DWORD newSectionFOA = pNewSectionHeader->PointerToRawData; //�����ڵ�FOA
	DWORD newSectionFileAddr = (DWORD)pNewFileBuffer + newSectionFOA; //�����ڵľ��Ե�ַ

	//��ʼ�ƶ�������
	DWORD exportTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportTableFOA = RvaToFileOffset(pNewFileBuffer, exportTableRVA);
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pNewFileBuffer + exportTableFOA);
	//1���ƶ�AddressOfFunctions
	DWORD funcAddrTableFOA = RvaToFileOffset(pNewFileBuffer, pExportTable->AddressOfFunctions);
	DWORD funcAddrTableAddr = (DWORD)pNewFileBuffer + funcAddrTableFOA;
	memcpy((void*)newSectionFileAddr, (void*)funcAddrTableAddr, (4 * (pExportTable->NumberOfFunctions)));
	//2���ƶ�AddressOfNameOrdinals
	DWORD funcOrdinalsTableFOA = RvaToFileOffset(pNewFileBuffer, pExportTable->AddressOfNameOrdinals);
	DWORD funcOrdinalsTableAddr = (DWORD)pNewFileBuffer + funcOrdinalsTableFOA;
	memcpy((void*)(newSectionFileAddr + (4 * (pExportTable->NumberOfFunctions))), (void*)funcOrdinalsTableAddr, (2 * (pExportTable->NumberOfNames)));
	//3���ƶ�AddressOfNames
	DWORD funcNameTableFOA = RvaToFileOffset(pNewFileBuffer, pExportTable->AddressOfNames);
	DWORD funcNameTableAddr = (DWORD)pNewFileBuffer + funcNameTableFOA;
	memcpy((void*)(newSectionFileAddr + (4 * (pExportTable->NumberOfFunctions)) + (2 * (pExportTable->NumberOfNames))), (void*)funcNameTableAddr, (4 * (pExportTable->NumberOfNames)));
	//4���ƶ����еĺ��������޸�AddressOfNames
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
	//5������IMAGE_EXPORT_DIRECTORY�ṹ
	memcpy((void*)newFuncName, pExportTable, sizeof(IMAGE_EXPORT_DIRECTORY));
	//6���޸�IMAGE_EXPORT_DIRECTORY�ṹ�е�AddressOfFunctions��AddressOfNameOrdinals��AddressOfNames
	PIMAGE_EXPORT_DIRECTORY pNewExportTable = (PIMAGE_EXPORT_DIRECTORY)newFuncName;
	pNewExportTable->AddressOfFunctions = pNewSectionHeader->VirtualAddress;
	pNewExportTable->AddressOfNameOrdinals = pNewSectionHeader->VirtualAddress + (4 * pExportTable->NumberOfFunctions);
	pNewExportTable->AddressOfNames = pNewSectionHeader->VirtualAddress + (4 * pExportTable->NumberOfFunctions) + (2 * pExportTable->NumberOfNames);
	//7���޸�Ŀ¼���е�ֵ��ָ���µ�IMAGE_EXPORT_DIRECTORY
	pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (DWORD)pNewExportTable - (DWORD)pNewFileBuffer - pNewSectionHeader->PointerToRawData + pNewSectionHeader->VirtualAddress;


	//����
	BOOL isOK = FALSE;
	isOK = MemoryTOFile(pNewFileBuffer, fileSize + 0x1000, FILEPATH_OUT_DLL);
	if (isOK)
	{
		printf("���̳ɹ���\n");
	}
	else
	{
		printf("����ʧ�ܣ�\n");
	}

	//�ͷ�������ڴ沢��ָ���ÿ�
	free(pFileBuffer);
	free(pNewFileBuffer);
	pFileBuffer = nullptr;
	pNewFileBuffer = nullptr;
}

void moveRelocationTable()
{
	void* pFileBuffer = nullptr;

	//��ȡ�ļ��������ڴ�ռ�
	DWORD fileSize = ReadPEFile(FILEPATH_IN_DLL, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("��ȡ�ļ��������ڴ�ռ�ʧ�ܣ�\n");
		return;
	}
	
	//����PEͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}
	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//����һ����
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	if (pOptionalHeader->SizeOfHeaders - ((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("���пռ䲻�����޷���ӽڱ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	void* pNewFileBuffer = malloc(fileSize + 0x1000);
	if (pNewFileBuffer == nullptr)
	{
		printf("�����ڴ�ռ�ʧ�ܣ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	//���ӽ����;����С
	pPEHeader->NumberOfSections += 1;
	pOptionalHeader->SizeOfImage += 0x1000;

	memset(pNewFileBuffer, 0, fileSize + 0x1000);
	memcpy(pNewFileBuffer, pFileBuffer, fileSize);

	//���»�ȡ����ͷ��ָ��
	pDosHeader = (PIMAGE_DOS_HEADER)pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 2;
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;

	//��ʼ���½�ͷ
	memcpy(pNewSectionHeader, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	memset((void*)((DWORD)pNewSectionHeader + IMAGE_SIZEOF_SECTION_HEADER), 0, IMAGE_SIZEOF_SECTION_HEADER);

	strncpy((char*)pNewSectionHeader->Name, ".newsec", IMAGE_SIZEOF_SHORT_NAME);
	pNewSectionHeader->Misc.VirtualSize = 0x1000;
	pNewSectionHeader->VirtualAddress = pLastSectionHeader->VirtualAddress + (DWORD)Align(max(pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->SizeOfRawData), pOptionalHeader->SectionAlignment);
	pNewSectionHeader->SizeOfRawData = 0x1000;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

	DWORD newSectionFOA = pNewSectionHeader->PointerToRawData; //�����ڵ�FOA
	DWORD newSectionFileAddr = (DWORD)pNewFileBuffer + newSectionFOA; //�����ڵľ��Ե�ַ

	
	printf("oldImageBase:%x\n", pOptionalHeader->ImageBase);
	pOptionalHeader->ImageBase += 0x1000;
	printf("newImageBase:%x\n", pOptionalHeader->ImageBase);
	
	//��ʼ�ƶ��ض�λ��
	DWORD pRelocationTableRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD pRelocationTableFOA = RvaToFileOffset(pNewFileBuffer, pRelocationTableRVA);
	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pNewFileBuffer + pRelocationTableFOA);

	//�����ض�λ��Ĵ�С
	DWORD sizeOfRelocationTable = 0;
	while (pRelocationTable->VirtualAddress != 0 && pRelocationTable->SizeOfBlock != 0)
	{
		
		sizeOfRelocationTable += pRelocationTable->SizeOfBlock;
		
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pNewFileBuffer + pRelocationTableFOA);
	//�ƶ��ض�λ��������
	memcpy((void*)newSectionFileAddr, pRelocationTable, sizeOfRelocationTable);
	
	//�޸��ض�λ����ΪpOptionalHeader->ImageBase += 0x1000;��
	PIMAGE_BASE_RELOCATION pNewRelocationTable = (PIMAGE_BASE_RELOCATION)newSectionFileAddr;
	while (pNewRelocationTable->VirtualAddress != 0 && pNewRelocationTable->SizeOfBlock != 0)
	{
		pNewRelocationTable->VirtualAddress += 0x1000;

		//������һ����
		pNewRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pNewRelocationTable + pNewRelocationTable->SizeOfBlock);
	}

	//�޸�Ŀ¼���е��ض�λ��ĵ�ַ
	pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = pNewSectionHeader->VirtualAddress;
	
	//����
	BOOL isOK = FALSE;
	isOK = MemoryTOFile(pNewFileBuffer, fileSize + 0x1000, FILEPATH_OUT_DLL);
	if (isOK)
	{
		printf("���̳ɹ���\n");
	}
	else
	{
		printf("����ʧ�ܣ�\n");
	}

	//�ͷ�������ڴ沢��ָ���ÿ�
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

	//��ȡ�ļ��������ڴ�ռ�
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if(fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("��ȡ�ļ��������ڴ�ռ�ʧ�ܣ�\n");
		return ;
	}

	//����PEͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;

	//�ҵ�������ַ
	DWORD importTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importTableFOA = RvaToFileOffset(pFileBuffer, importTableRVA);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + importTableFOA);
	
	while (pImportTable->OriginalFirstThunk != 0 && pImportTable->FirstThunk != 0)
	{
		//���dll������
		DWORD dllNameRVA = pImportTable->Name;
		DWORD dllNameFOA = RvaToFileOffset(pFileBuffer, dllNameRVA);
		char* dllName = (char*)((DWORD)pFileBuffer + dllNameFOA);
		printf("*****************************************************\n");
		printf("%s\n", dllName);

		//����OriginalFirstThunk
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
					printf("������ŵ�����%Xh\n", (INTTable[i] & 0x7FFFFFFF));
				}
				else
				{
					DWORD INT_nameImportTableFOA = RvaToFileOffset(pFileBuffer, INTTable[i]);
					PIMAGE_IMPORT_BY_NAME pNameImportTable = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + INT_nameImportTableFOA);
					printf("�������ֵ�����Hint-Name:%X-%s\n",pNameImportTable->Hint,pNameImportTable->Name);
				}
			}
			else
			{
				break;
			}
		}
		printf("-----------------------------------------------------\n");
		

		//����FirstThunk
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
					printf("������ŵ�����%Xh\n", (IATTable[j] & 0x7FFFFFFF));
				}
				else
				{
					DWORD IAT_nameImportTableFOA = RvaToFileOffset(pFileBuffer, IATTable[j]);
					PIMAGE_IMPORT_BY_NAME pNameImportTable = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + IAT_nameImportTableFOA);
					printf("�������ֵ�����Hint-Name:%X-%s\n", pNameImportTable->Hint, pNameImportTable->Name);
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

	//��ȡ�ļ��������ڴ�ռ�
	DWORD fileSize = ReadPEFile(FILEPATH, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("��ȡ�ļ��������ڴ�ռ�ʧ�ܣ�\n");
		return ;
	}

	//����PEͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
	}

	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;


	//�ҵ��󶨵����
	DWORD boundImportTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
	printf("%x\n", boundImportTableRVA);
	DWORD boundImportTableFOA = RvaToFileOffset(pFileBuffer, boundImportTableRVA);
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportTable = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + boundImportTableFOA);


	//����󶨵�����������Ϣ
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

	//�ͷ��ڴ�
	free(pFileBuffer);
	pFileBuffer = nullptr;
}


void injectByImportTable()
{
	void* pFileBuffer = nullptr;

	//��ȡ�ļ��������ڴ�ռ�
	DWORD fileSize = ReadPEFile(FILEPATH_IN, &pFileBuffer);
	if (fileSize == 0 || pFileBuffer == nullptr)
	{
		printf("��ȡ�ļ��������ڴ�ռ�ʧ�ܣ�\n");
		return ;
	}

	//����PEͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("��Ч��DOSͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return ;
	}

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("��Ч��PEͷ��\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	PIMAGE_FILE_HEADER pPEHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);

	//����һ����
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + (pPEHeader->NumberOfSections - 1);
	if (pOptionalHeader->SizeOfHeaders - ((DWORD)pLastSectionHeader + IMAGE_SIZEOF_SECTION_HEADER) < 2 * IMAGE_SIZEOF_SECTION_HEADER)
	{
		printf("���пռ䲻�����޷���ӽڱ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	DWORD newFileSize = fileSize + 0x500;
	void* pNewFileBuffer = malloc(newFileSize);
	if (pNewFileBuffer == nullptr)
	{
		printf("�����ڴ�ռ�ʧ�ܣ�\n");
		free(pFileBuffer);
		pFileBuffer = nullptr;
		return;
	}

	//���ӽ����;����С
	pPEHeader->NumberOfSections += 1;
	pOptionalHeader->SizeOfImage += 0x500;

	memset(pNewFileBuffer, 0, newFileSize);
	memcpy(pNewFileBuffer, pFileBuffer, fileSize);

	//���»�ȡ����ͷ��ָ��
	pDosHeader = (PIMAGE_DOS_HEADER)pNewFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pPEHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	pLastSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 2;
	PIMAGE_SECTION_HEADER pNewSectionHeader = pSectionHeader + pPEHeader->NumberOfSections - 1;

	//��ʼ���½ڱ�
	memcpy(pNewSectionHeader, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	memset((void*)((DWORD)pNewSectionHeader + IMAGE_SIZEOF_SECTION_HEADER), 0, IMAGE_SIZEOF_SECTION_HEADER);
	//�޸��½ڱ�����
	strncpy((char*)pNewSectionHeader->Name, ".newsec", IMAGE_SIZEOF_SHORT_NAME);
	pNewSectionHeader->Misc.VirtualSize = 0x500;
	pNewSectionHeader->VirtualAddress = pLastSectionHeader->VirtualAddress + (DWORD)Align(max(pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->SizeOfRawData), pOptionalHeader->SectionAlignment);
	pNewSectionHeader->SizeOfRawData = 0x500;
	pNewSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	pNewSectionHeader->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	pNewSectionHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;
	pNewSectionHeader->Characteristics |= IMAGE_SCN_MEM_READ;

	DWORD newSectionFOA = pNewSectionHeader->PointerToRawData; //�����ڵ�FOA
	DWORD newSectionFileAddr = (DWORD)pNewFileBuffer + newSectionFOA; //�����ڵľ��Ե�ַ

	//�ƶ�ԭ�����
	DWORD importTableRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importTableFOA = RvaToFileOffset(pNewFileBuffer, importTableRVA);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pNewFileBuffer + importTableFOA);
	DWORD sizeOfImportTable = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	// ���Ƶ�����½ڣ�������½ڵ�ʣ�ಿ��
	memcpy((void*)newSectionFileAddr, pImportTable, sizeOfImportTable);
	memset((void*)((DWORD)newSectionFileAddr + sizeOfImportTable), 0, 0x500 - sizeOfImportTable);

	
	//��ӵ����
	PIMAGE_IMPORT_DESCRIPTOR pNewImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)newSectionFileAddr + sizeOfImportTable - sizeof(IMAGE_IMPORT_DESCRIPTOR));
	memset((void*)((DWORD)pNewImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR)), 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	//���INT���IAT��
	PIMAGE_THUNK_DATA32 INTTable = (PIMAGE_THUNK_DATA32)((DWORD)pNewImportTable + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR));
	PIMAGE_THUNK_DATA32 IATTable = (PIMAGE_THUNK_DATA32)((DWORD)INTTable + 0x8);
	pNewImportTable->OriginalFirstThunk = (DWORD)INTTable - (DWORD)pNewFileBuffer - newSectionFOA + pNewSectionHeader->VirtualAddress;
	pNewImportTable->FirstThunk = (DWORD)IATTable - (DWORD)pNewFileBuffer - newSectionFOA + pNewSectionHeader->VirtualAddress;
	//���IMAGE_IMPORT_BY_NAME
	PIMAGE_IMPORT_BY_NAME importByNameTable = (PIMAGE_IMPORT_BY_NAME)((DWORD)IATTable + 0x8);
	char funcName[] = "ExportFunction";
	strncpy((char*)importByNameTable->Name, funcName, sizeof(funcName));
	importByNameTable->Hint = 0;

	INTTable->u1.AddressOfData = ((DWORD)importByNameTable - (DWORD)pNewFileBuffer - newSectionFOA + pNewSectionHeader->VirtualAddress) & 0x7FFFFFFF;
	IATTable->u1.AddressOfData = ((DWORD)importByNameTable - (DWORD)pNewFileBuffer - newSectionFOA + pNewSectionHeader->VirtualAddress) & 0x7FFFFFFF;

	//�洢dll����
	char dllName[] = "InjectDll.dll";
	DWORD dllNameFileAddr = (DWORD)importByNameTable + sizeof(PIMAGE_IMPORT_BY_NAME) + sizeof(funcName) - 1;
	strncpy((char*)dllNameFileAddr, dllName, sizeof(dllName) + 1);

	//��������������Name����
	DWORD dllNameRVA = dllNameFileAddr - (DWORD)pNewFileBuffer - pNewSectionHeader->PointerToRawData + pNewSectionHeader->VirtualAddress;
	pNewImportTable->Name = dllNameRVA;


	//����IMAGE_DATA_DIRECTORY�ṹ��VirtualAddress��Size
	pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pNewSectionHeader->VirtualAddress;
	DWORD newSizeOfImportTable = sizeOfImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR);
	pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = newSizeOfImportTable;

	
	

	//����
	BOOL isOK = FALSE;
	isOK = MemoryTOFile(pNewFileBuffer, newFileSize, FILEPATH_OUT);
	if (isOK)
	{
		printf("���̳ɹ���\n");
	}
	else
	{
		printf("����ʧ�ܣ�\n");
	}

	//�ͷ��ڴ�
	free(pFileBuffer);
	free(pNewFileBuffer);
	pFileBuffer = nullptr;
	pNewFileBuffer = nullptr;
}