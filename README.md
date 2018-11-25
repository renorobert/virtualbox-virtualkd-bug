# VirtualBox VirtualKD buffer overflow bug - CVE-2017-10233

Debugger security is not a new topic of discussion. There are couple of awesome research by j00ru [2] and Alex [3] published already. VirtualKD is a solution to improve Windows kernel debugging performance. In order to support this, VirtualBox has a small device in src/VBox/Devices/Misc/VirtualKD.cpp. This device is not enabled by default. But what makes it interesting is, VirtualKD is also used for analyzing untrusted code. Any vulnerability in VirtualKD or the VirtualBox device for VirtualKD would affect the host system.

VirtualKD device uses I/O port 0x5658 and 0x5659 for communication. When the guest wants to send data, it is passed as VKDREQUESTHDR structure followed by data

```c
typedef struct VKDREQUESTHDR
{
    unsigned cbData;
    unsigned cbReplyMax;
} VKDREQUESTHDR; 
```

The guest physical address of the request is written to the I/O port. On the host side the request is handled as below:

```c
static DECLCALLBACK(int) vkdPortWrite(PPDMDEVINS pDevIns, void *pvUser, RTIOPORT Port, uint32_t u32, unsigned cb)
{
. . .
    if (Port == 0x5659)
    {
        VKDREQUESTHDR RequestHeader = {0, };
        int rc = PDMDevHlpPhysRead(pDevIns, (RTGCPHYS)u32, &RequestHeader, sizeof(RequestHeader)); 
. . .
        rc = PDMDevHlpPhysRead(pDevIns, (RTGCPHYS)(u32 + sizeof(RequestHeader)), pThis->abCmdBody, RequestHeader.cbData);
. . .
        cbReply = pThis->pKDClient->OnRequest(pThis->abCmdBody,
                                              RequestHeader.cbData,
                                              &pReply);
. . .
}
```

First the request header is copied using PDMDevHlpPhysRead() into RequestHeader. Then RequestHeader.cbData number of bytes are copied into abCmdBody.

```c
typedef struct VIRTUALKD
{
    bool fOpenChannelDetected;
    bool fChannelDetectSuccessful;
    RTLDRMOD hLib;
    IKDClient *pKDClient;
    char abCmdBody[262144];
} VIRTUALKD;
```

In this case, abCmdBody has a fixed size of 0x40000 bytes and RequestHeader.cbData is not validated leading to buffer overflow. Below is the patch:

```c
--- VirtualBox-5.1.22/src/VBox/Devices/Misc/VirtualKD.cpp
+++ VirtualBox-5.1.24/src/VBox/Devices/Misc/VirtualKD.cpp
@@ -73,7 +73,7 @@
     bool fChannelDetectSuccessful;
     RTLDRMOD hLib;
     IKDClient *pKDClient;
-    char abCmdBody[262144];
+    char abCmdBody[_256K];
 } VIRTUALKD;


@@ -107,17 +107,17 @@
     {
         VKDREQUESTHDR RequestHeader = {0, };
         int rc = PDMDevHlpPhysRead(pDevIns, (RTGCPHYS)u32, &RequestHeader, sizeof(RequestHeader));
-        if (!RT_SUCCESS(rc) || !RequestHeader.cbData)
+        if (   !RT_SUCCESS(rc)
+            || !RequestHeader.cbData)
             return VINF_SUCCESS;
-        rc = PDMDevHlpPhysRead(pDevIns, (RTGCPHYS)(u32 + sizeof(RequestHeader)), pThis->abCmdBody, RequestHeader.cbData);
+
+        unsigned cbData = RT_MIN(RequestHeader.cbData, sizeof(pThis->abCmdBody));
+        rc = PDMDevHlpPhysRead(pDevIns, (RTGCPHYS)(u32 + sizeof(RequestHeader)), pThis->abCmdBody, cbData);
         if (!RT_SUCCESS(rc))
             return VINF_SUCCESS;

         char *pReply = NULL;
-        unsigned cbReply;
-        cbReply = pThis->pKDClient->OnRequest(pThis->abCmdBody,
-                                              RequestHeader.cbData,
-                                              &pReply);
+        unsigned cbReply = pThis->pKDClient->OnRequest(pThis->abCmdBody, cbData, &pReply);

         if (!pReply)
             cbReply = 0;
```

This bug was fixed in Oracle Critical Patch Update - July 2017 [4]

**References and further readings:**

[1] Debugger Security  
https://docs.microsoft.com/en-us/visualstudio/debugger/debugger-security?view=vs-2017  
[2] Attacking the Host via Remote Kernel Debugger  
https://j00ru.vexillium.org/?p=405  
[3] Debugger-based Target-to-Host Cross-System Attacks   
https://recon.cx/2010/speakers.html#debugger  
[4] Oracle Critical Patch Update Advisory - July 2017  
https://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html  
[5] VirtualKD  
http://virtualkd.sysprogs.org/
