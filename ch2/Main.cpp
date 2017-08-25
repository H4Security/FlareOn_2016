#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

int main()
{
//--------------------------------------------------------------------
// Declare variables.
//
// hProv:           Handle to a cryptographic service provider (CSP). 
//                  This example retrieves the default provider for  
//                  the PROV_RSA_AES provider type.  
// hHash:           Handle to the hash object needed to create a hash.
// hKey:            Handle to a symmetric key. This example creates a 
//                  key for the RC4 algorithm.

// pbHash:          Pointer to the hash.
// dwDataLen:       Length, in bytes, of the hash.
// Data1:           Password string used to create a symmetric key.
// Data2:           Name of file that use as Iv.

// 
HCRYPTPROV  hProv       = NULL;
HCRYPTHASH  hHash       = NULL;
HCRYPTKEY   hKey        = NULL;
HCRYPTHASH  hHmacHash   = NULL;
HCRYPTHASH  hMd5Hash	= NULL;
PBYTE       pbHash      = NULL;
DWORD       dwDataLen   = 0;
BYTE        Data1[]     = {0x74,0x68,0x6f,0x73,0x65,0x66,0x69,0x6c,0x65,0x73,0x72,0x65,0x61,0x6c,
0x6c,0x79,0x74,0x69,0x65,0x64,0x74,0x68,0x65,0x66,0x6f,0x6c,0x64,0x65,0x72,0x74,0x6f,0x67,0x65,
0x74,0x68,0x65,0x72};//"thosefilesreallytiedthefoldertogether\0";
BYTE        Data2[]     = {0x62,0x75,0x73,0x69,0x6e,0x65,0x73,0x73,0x70,0x61,0x70,0x65,0x72,0x73,
							0x2e,0x64,0x6f,0x63};//"businesspapers.doc";
HMAC_INFO   HmacInfo;
char filename[]="BusinessPapers.doc\0";
//--------------------------------------------------------------------
// Zero the HMAC_INFO structure and use the SHA1 algorithm for
// hashing.

ZeroMemory(&HmacInfo, sizeof(HmacInfo));
HmacInfo.HashAlgid = CALG_SHA1;

//--------------------------------------------------------------------
// Acquire a handle to the default RSA_AES cryptographic service provider.

if (!CryptAcquireContext(
    &hProv,                   // handle of the CSP
    NULL,                     // key container name
    NULL,                     // CSP name
    PROV_RSA_AES,            // provider type
    0))     // no key access is requested
{
	if (!CryptAcquireContext(
		&hProv,                   // handle of the CSP
		NULL,                     // key container name
		NULL,                     // CSP name
		PROV_RSA_AES,            // provider type
		CRYPT_NEWKEYSET))     // no key access is requested
	{
	   printf(" Error in AcquireContext 0x%08x \n",
			  GetLastError());
	   goto ErrorExit;
	}
}

//--------------------------------------------------------------------
// Derive a symmetric key from a hash object by performing the
// following steps:
//    1. Call CryptCreateHash to retrieve a handle to a hash object.
//    2. Call CryptHashData to add a text string (password) to the 
//       hash object.
//    3. Call CryptDeriveKey to create the symmetric key from the
//       hashed password derived in step 2.
// You will use the key later to create an HMAC hash object. 

if (!CryptCreateHash(
    hProv,                    // handle of the CSP
    CALG_SHA1,                // hash algorithm to use
    0,                        // hash key
    0,                        // reserved
    &hHash))                  // address of hash object handle
{
   printf("Error in CryptCreateHash 0x%08x \n",
          GetLastError());
   goto ErrorExit;
}

if (!CryptHashData(
    hHash,                    // handle of the hash object
    Data1,                    // password to hash
    sizeof(Data1),            // number of bytes of data to add
    0))                       // flags
{
   printf("Error in CryptHashData 0x%08x \n", 
          GetLastError());
   goto ErrorExit;
}

if (!CryptDeriveKey(
    hProv,                    // handle of the CSP
	CALG_AES_256,                 // algorithm ID 0x6610
    hHash,                    // handle to the hash object
    0,                        // flags
    &hKey))                   // address of the key handle
{
   printf("Error in CryptDeriveKey 0x%08x \n", 
          GetLastError());
   goto ErrorExit;
}
/*const BYTE MODE_ECB = 0x1;// (BYTE) CRYPT_MODE_CBC;
if (!CryptSetKeyParam(
    hKey,                    // A handle to the key for which values are to be set.
    KP_MODE,                // cipher mode to be used
    &MODE_ECB,                     // block cipher mode 
    0))              // Used only when dwParam is KP_ALGID
{
   printf("Error in CryptSetKeyParam 0x%08x \n", 
          GetLastError());
   goto ErrorExit;
}*/


if (!CryptCreateHash(
    hProv,                    // handle of the CSP.
    CALG_MD5,                // HMAC hash algorithm ID
    0,                     // key for the hash (see above)
    0,                        // reserved
    &hMd5Hash))              // address of the hash handle
{
   printf("Error in CryptCreateHash 0x%08x \n", 
          GetLastError());
   goto ErrorExit;
}

if (!CryptHashData(
    hMd5Hash,                // handle of the HMAC hash object
    Data2,                    // message to hash
    sizeof(Data2),            // number of bytes of data to add
    0))                       // flags
{
   printf("Error in CryptHashData 0x%08x \n", 
          GetLastError());
   goto ErrorExit;
}
BYTE Md5ResultFileNAme[16]="";
DWORD DataLenth;
if (!CryptGetHashParam(
    hMd5Hash,                // handle of the HMAC hash object
    HP_HASHVAL,             // setting an HP_HASHVAL object
    Md5ResultFileNAme,         // the md5 result object
    &DataLenth,            // number of bytes of data to add
	0))                       // reserved
{
   printf("Error in CryptSetHashParam 0x%08x \n", 
          GetLastError());
   goto ErrorExit;
}

if (!CryptSetKeyParam(
    hKey,                    // A handle to the key for which values are to be set.
	KP_IV,                // cipher mode to be used
    Md5ResultFileNAme,                     // block cipher mode 
    0))              // Used only when dwParam is KP_ALGID
{
   printf("Error in CryptSetKeyParam 0x%08x \n", 
          GetLastError());
   goto ErrorExit;
}


 HANDLE hFileRead = CreateFile(filename,
        GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

 DWORD dwFileSize = GetFileSize(hFileRead,NULL);

 HANDLE hFileWrite = CreateFile(filename,
	 GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);
 BYTE DecryptMem[0x4011];
 DWORD NumberOfReading = 16;
 BOOLEAN finall=0;
 while (ReadFile(hFileRead,DecryptMem,0x4000,&NumberOfReading,NULL) && !finall )
 {
	 if (NumberOfReading < 0x4000)
		finall =1;
		 if (!CryptDecrypt(
				hKey,                // handle of the HMAC hash object
				0,                    // message to hash
				0,            // number of bytes of data to add
				0,
				DecryptMem,
				&NumberOfReading
				))                       // flags
			{
			   printf("Error in CryptDecrypt 0x%08x \n", 
					  GetLastError());
			   goto ErrorExit;
			}

	 
	 WriteFile(
		 hFileWrite,
		 DecryptMem,
		 0x4000,
		 &NumberOfReading,
		 NULL);
 }


ErrorExit:
    
    if(hKey)
        CryptDestroyKey(hKey);
    if(hHash)
        CryptDestroyHash(hHash);    
    if(hProv)
        CryptReleaseContext(hProv, 0);
    if(pbHash)
        free(pbHash);
    return 0;
}
