#include "hs_types.h"

#define LIC_USER            "user"
#define LIC_DEV             "dev"
#define LIC_MAC             "mac"
#define LIC_MD5             "md5"

#define LIC_FILE            "hs.lic"

#define LIC_BUFF_LEN        64

typedef struct {
    CHAR arrcUser[LIC_BUFF_LEN]; 
    CHAR arrcDev[LIC_BUFF_LEN];
    CHAR arrcMac[LIC_BUFF_LEN]; 
    CHAR arrcMd5[LIC_BUFF_LEN];
    // other 
} HS_LICENSE_S;

typedef struct {
    UCHAR digest[MD5_DIGEST_LENGTH];
    UCHAR hex[MD5_DIGEST_LENGTH * 2 + 1];
} HS_MD5_S;

INT32 GenLicense(CHAR *pcInfo);

INT32 CheckLicense(CHAR *pcLic);
