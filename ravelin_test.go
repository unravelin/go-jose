package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

/*
	These tests replicate the various test cases in the
	EMVCo 3-D Secure App-based Crypto Worked Samples document
	Version 3.0.0
	October 2019

	Examples are numbered 1-12:

	• Examples 1-4 illustrate encryption of device information by the SDK using either RSA-OAEP-256 or ECDH-ES for key agreement and either A128CBC-HS256 or A128GCM for data encryption
	• Examples 5 and 6 illustrate ACS signed content using either RSA-based PS256 or EC-based ES256
	• Examples 7 and 8 illustrate ACS, and then SDK, key derivation using ECDH-ES, in preparation for Examples 9-12
	• Examples 9-12 illustrate SDK, and then ACS, message encryption using either A128CBC-HS256 or A128GCM
*/

var dsRSAPublicKeyJSON = []byte(`{
	"kty": "RSA",
	"kid": "UUIDkeyidentifierforDS", "use": "enc",
	"n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
	"e": "AQAB"
	}`)

var dsRSAPrivateKeyJSON = []byte(`{
	"kty": "RSA",
	"kid": "UUIDkeyidentifierforDS", 
	"use": "enc",
	"n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
	"e": "AQAB",
	"d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",
	"p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",
	"q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",
	"dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",
	"dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",
	"qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"
  }`)

var dsECPublicKeyJSON = []byte(`{
	"kty": "EC",
	"crv": "P-256",
	"kid": "UUIDkeyidentifierforDS-EC",
	"x":   "2_v-MuNZccqwM7PXlakW9oHLP5XyrjMG1UVS8OxYrgA",
	"y":   "rm1ktLmFIsP2R0YyJGXtsCbaTUesUK31Xc04tHJRolc"
}`)

var dsECPrivateKeyJSON = []byte(`{
	"kty": "EC",
	"crv": "P-256",
	"kid": "UUIDkeyidentifierforDS-EC",
	"x":   "2_v-MuNZccqwM7PXlakW9oHLP5XyrjMG1UVS8OxYrgA",
	"y":   "rm1ktLmFIsP2R0YyJGXtsCbaTUesUK31Xc04tHJRolc",
	"d":   "rAZel3KoyQbPejeMRfKzwnqvZfX23fIKek4OKX-5Iu0"
}`)

var sdkEphemeralECPrivateKeyJSON = []byte(`{
	"kty": "EC",
	"crv": "P-256",
	"x":   "C1PL42i6kmNkM61aupEAgLJ4gF1ZRzcV7lqo1TG0mL4",
	"y":   "cNToWLSdcFQKG--PGVEUQrIHP8w6TcRyj0pyFx4-ZMc",
	"d":   "iyn--IbkBeNoPu8cN245L6pOQWt2lTH8V0Ds92jQmWA"
}`)

var testDirectoryServerID = "A000000802"

var deviceInfoStr = `{"DV":"1.0","DD":{"C001":"Android","C002":"HTC One_M8","C004":"5.0.1","C005":"en_US","C006":"Eastern Standard Time","C007":"06797903-fb61-41ed-94c2-4d2b74e27d18","C009":"John's Android Device"},"DPNA":{"C010":"RE01","C011":"RE03"},"SW":["SW01","SW04"]}`
var acsContentStr = `{"acsEphemPubKey":{"kty":"EC","crv":"P-256","x":"mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA","y":"8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs"},"sdkEphemPubKey":{"kty":"EC","crv":"P-256","x":"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0","y":"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw"},"acsURL":"http://acsserver.domainname.com"}`

var acsRSAPrivateKeyJSON = []byte(`{
	"kty":"RSA",
	"use":"sig",
	"n":"kNrPIBDXMU6fcyv5i-QHQAQ-K8gsC3HJb7FYhYaw8hXbNJa-t8q0lDKwLZgQXYV-ffWxXJv5GGrlZE4GU52lfMEegTDzYTrRQ3tepgKFjMGg6Iy6fkl1ZNsx2gEonsnlShfzA9GJwRTmtKPbk1s-hwx1IU5AT-AIelNqBgcF2vE5W25_SGGBoaROVdUYxqETDggM1z5cKV4ZjDZ8-lh4oVB07bkac6LQdHpJUUySH_Er20DXx30Kyi97PciXKTS-QKXnmm8ivyRCmux22ZoPUind2BKC5OiG4MwALhaL2Z2k8CsRdfy-7dg7z41Rp6D0ZeEvtaUp4bX4aKraL4rTfw",
	"e":"AQAB",
	"d":"ZLe_TIxpE9-W_n2VBa-HWvuYPtjvxwVXClJFOpJsdea8g9RMx34qEOEtnoYc2un3CZ3LtJi-mju5RAT8YSc76YJds3ZVw0UiO8mMBeG6-iOnvgobobNx7K57-xjTJZU72EjOr9kB7z6ZKwDDq7HFyCDhUEcYcHFVc7iL_6TibVhAhOFONWlqlJgEgwVYd0rybNGKifdnpEbwyHoMwY6HM1qvnEFgP7iZ0YzHUT535x6jj4VKcdA7ZduFkhUauysySEW7mxZM6fj1vdjJIy9LD1fIz30Xv4ckoqhKF5GONU6tNmMmNgAD6gIViyEle1PrIxl1tBhCI14bRW-zrpHgAQ",
	"p": "yKWYoNIAqwMRQlgIBOdT1NIcbDNUUs2Rh-pBaxD_mIkweMt4Mg-0-B2iSYvMrs8horhonV7vxCQagcBAATGW-hAafUehWjxWSH-3KccRM8toL4e0q7M-idRDOBXSoe7Z2-CV2x_ZCY3RP8qp642R13WgXqGDIM4MbUkZSjcY9-c",
	"q": "uND4o15V30KDzf8vFJw589p1vlQVQ3NEilrinRUPHkkxaAzDzccGgrWMWpGxGFFnNL3w5CqPLeU76-5IVYQq0HwYVl0hVXQHr7sgaGu-483Ad3ENcL23FrOnF45m7_2ooAstJDe49MeLTTQKrSIBl_SKvqpYvfSPTczPcZkh9Kk",
	"dp": "jmTnEoq2qqa8ouaymjhJSCnsveUXnMQC2gAneQJRQkFqQu-zV2PKPKNbPvKVyiF5b2-L3tM3OW2d2iNDyRUWXlT7V5l0KwPTABSTOnTqAmYChGi8kXXdlhcrtSvXldBakC6saxwI_TzGGY2MVXzc2ZnCvCXHV4qjSxOrfP3pHFU",
	"dq": "R9FUvU88OVzEkTkXl3-5-WusE4DjHmndeZIlu3rifBdfLpq_P-iWPBbGaq9wzQ1c-J7SzCdJqkEJDv5yd2C7rnZ6kpzwBh_nmL8zscAk1qsunnt9CJGAYz7-sGWy1JGShFazfP52ThB4rlCJ0YuEaQMrIzpY77_oLAhpmDA0hLk",
	"qi": "S8tC7ZknW6hPITkjcwttQOPLVmRfwirRlFAViuDb8NW9CrV_7F2OqUZCqmzHTYAumwGFHI1WVRep7anleWaJjxC_1b3fq_al4qH3Pe-EKiHg6IMazuRtZLUROcThrExDbF5dYbsciDnfRUWLErZ4N1Be0bnxYuPqxwKd9QZwMo0"
}`)

var acsECPrivateKeyJSON = []byte(`{
	"kty":"EC",
	"crv":"P-256",
	"x":"36H4sHOgIrtWIObxvXilx3gwlYfYd1TKjdv8idQlhlI",
	"y":"KnwGPyr56s6jvi23qMRMzMBpOnMtnmgYNlx5l8aYzt0",
	"d":"6-ySVPXPZBVkZ1t951KFgWL_AQrG_wk9BrmV3v3fs5k"
}`)

var acsDsRsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIDeTCCAmGgAwIBAgIQbS4C4BSig7uuJ5uDpeT4WDANBgkqhkiG9w0BAQsFADBH
MRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEX
MBUGA1UEAwwOUlNBIEV4YW1wbGUgRFMwHhcNMTcxMTIxMTE1NDAyWhcNMjcxMjMx
MTMzMDAwWjBIMRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYH
ZXhhbXBsZTEYMBYGA1UEAwwPUlNBIEV4YW1wbGUgQUNTMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAkNrPIBDXMU6fcyv5i+QHQAQ+K8gsC3HJb7FYhYaw
8hXbNJa+t8q0lDKwLZgQXYV+ffWxXJv5GGrlZE4GU52lfMEegTDzYTrRQ3tepgKF
jMGg6Iy6fkl1ZNsx2gEonsnlShfzA9GJwRTmtKPbk1s+hwx1IU5AT+AIelNqBgcF
2vE5W25/SGGBoaROVdUYxqETDggM1z5cKV4ZjDZ8+lh4oVB07bkac6LQdHpJUUyS
H/Er20DXx30Kyi97PciXKTS+QKXnmm8ivyRCmux22ZoPUind2BKC5OiG4MwALhaL
2Z2k8CsRdfy+7dg7z41Rp6D0ZeEvtaUp4bX4aKraL4rTfwIDAQABo2AwXjAMBgNV
HRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUktwf6ZpTCxjYKw/B
LW6PeiNX4swwHwYDVR0jBBgwFoAUw4MCnbwD6m2wpnoQ2sND8GryPN4wDQYJKoZI
hvcNAQELBQADggEBAGuNHxv/BR6j7lCPysm1uhrbjBOqdrhJMR/Id4dB2GtdEScl
3irGPmXyQ2SncTWhNfsgsKDZWp5Bk7+Otnty0eNUMk3hZEqgYjxhzau048XHbsfG
voJaMGZZNTwUvTUz2hkkhgpx9yQAKIA2LzFKcgYhelPu4GW5rtEuxu3IS6WYy3D1
GtF3naEWkjUra8hQOhOl2S+CYHmRd6lGkXykVDajMgd2AJFzXdKLxTt0OYrWDGlU
SzGACRBCd5xbRmATIldtccaGqDN1cNWv0I/bPN8EpKS6B0WaZcPasItKWpDC85Jw
1GrDxdhwoKHoxtSG+odiTwB5zLbrn2OsRE5bV7E=
-----END CERTIFICATE-----`

var acsDsEcCertPEM = `-----BEGIN CERTIFICATE-----
MIICrTCCAZWgAwIBAgIQbS4C4BSig7uuJ5uDpeT4WTANBgkqhkiG9w0BAQsFADBH
MRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEX
MBUGA1UEAwwOUlNBIEV4YW1wbGUgRFMwHhcNMTcxMTIxMTU0MzI3WhcNMjcxMjMx
MTMzMDAwWjBHMRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYH
ZXhhbXBsZTEXMBUGA1UEAwwORUMgRXhhbXBsZSBBQ1MwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATfofiwc6Aiu1Yg5vG9eKXHeDCVh9h3VMqN2/yJ1CWGUip8Bj8q
+erOo74tt6jETMzAaTpzLZ5oGDZceZfGmM7do2AwXjAMBgNVHRMBAf8EAjAAMA4G
A1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU0AWtDHR/vlQrRAz4aKgJBlnFjEswHwYD
VR0jBBgwFoAUw4MCnbwD6m2wpnoQ2sND8GryPN4wDQYJKoZIhvcNAQELBQADggEB
AEqlERewUCeEttAkC0F16Hjjxfv1Wa8naDmaRL99Q0/qqUN8w0qwpAPF7wn2afLf
aGd+5uZEb1TNYwV9Aw9L/s3BcSTERIl6OEWn+x7ctOmHy2vv7mitaUrileGodenm
/faDdy5VgKYj+KsMVM2sNVaekX+T0swACX9B90unZxa6256t2OJ2QV5zu3sYO1N0
j9v7+yF+Fgx014Nrw7/Xt8ILGF58NxbQhkhkfWSfHtaE5moBAbWRuFTFbkBf45SK
e0UMiU5Lac9xI0O7XCD+zNB5mws4NO2AYvyxHq9X+a64IhXclXngPQMrUqMoLWI1
66gRJSvQEWsILIUtx2wsiYs=
-----END CERTIFICATE-----`

var sdkDsRootCertPEM = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIQbS4C4BSig7uuJ5uDpeT4VjANBgkqhkiG9w0BAQsFADBH
MRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEX
MBUGA1UEAwwOUlNBIEV4YW1wbGUgRFMwHhcNMTcxMTIxMTE0ODQ5WhcNMjcxMjMx
MTQwMDAwWjBHMRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYH
ZXhhbXBsZTEXMBUGA1UEAwwOUlNBIEV4YW1wbGUgRFMwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCfgQ+0A4Jz0CWR5Ac/MdK2ABuCzttNkvBQFl1Hz8q4
o8Qct3isdVN5P475dXaNGiN02HElZMO813uepDRUSJlAfP8AmZIKkxokxEFIUqsp
vbCpXAZT82xg5gv5C2JY3aVvNwR7pcLR0CmvnJ1AuseqQceKDdEGit1pnoCP6gEe
oUQdik97tOl7459V8d3UTpxLozUVlwPU00tgPmUUek8j1tPAmWx17e6EaoLRkK4Q
eDyWHPA4eu0hBtLQVVtv2Tf61VNTh+D/cv++eJQUArC4IuoqdLYFjB2r+bNKdstj
uH+qLGhHuOKDf/+RGG5rHBSRHPmJqJCSqBzmAd2s0/nPAgMBAAGjRTBDMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTDgwKdvAPq
bbCmehDaw0PwavI83jANBgkqhkiG9w0BAQsFAAOCAQEAOUcKqpzNQ6lr0PbDSsns
D6onfi+8j3TD0xG0zBSf+8G4zs8Zb6vzzQ5qHKgfr4aeen8Pw0cw2KKUJ2dFaBqj
n3/6/MIZbgaBvXKUbmY8xCxKQ+tOFc3KWIu4pSaO50tMPJjU/lP35bv19AA9vs9M
TKY2qLf88bmoNYT3W8VSDcB58KBHa7HVIPx7BUUtSyb2N2Jqx5AOiYy4NarhB3hV
ftkZBmCzi2Qw50KWIgTFYcIVeRTx3Js/F0IuEdgZHBK2gmO7fdM7+QKYm83401vl
YRNCXfIZ0H9E1V3NddqJuqIutdUajckSzMhXdNCJqfI4FAQAymTWGL3/lZyr/30x
Fg==
-----END CERTIFICATE-----`

func TestDerivingECCek(t *testing.T) {

	// This test checks the custom function to derived the ECDHES cek works as expected

	// init expected keys from JSON representations
	var dsPublicJWK JSONWebKey
	err := dsPublicJWK.UnmarshalJSON(dsECPublicKeyJSON)
	require.NoError(t, err)
	require.True(t, dsPublicJWK.Valid())

	var sdkEphemeralECPrivateJWK JSONWebKey
	err = sdkEphemeralECPrivateJWK.UnmarshalJSON(sdkEphemeralECPrivateKeyJSON)
	require.NoError(t, err)
	require.True(t, sdkEphemeralECPrivateJWK.Valid())

	// cast keys to real types
	var ok bool
	var dsPublicKey *ecdsa.PublicKey
	dsPublicKey, ok = dsPublicJWK.Key.(*ecdsa.PublicKey)
	require.True(t, ok)

	var sdkEphemeralECPrivateKey *ecdsa.PrivateKey
	sdkEphemeralECPrivateKey, ok = sdkEphemeralECPrivateJWK.Key.(*ecdsa.PrivateKey)
	require.True(t, ok)

	deriveCek := createCustomDeriveECDHES(testDirectoryServerID)

	expectedCek := "A79A1FD4598AAEDC6738B3412BE4958E82BA4A263483A2ABD478BEB547E41952"

	cek := deriveCek("", []byte{}, []byte{}, sdkEphemeralECPrivateKey, dsPublicKey, 32)

	hexCek := strings.ToUpper(hex.EncodeToString(cek))

	require.Equal(t, expectedCek, hexCek)
}

func TestSDKEncDataExamples(t *testing.T) {

	tests := []struct {
		name                         string
		keyAlg                       KeyAlgorithm
		encAlg                       ContentEncryption
		dsPrivateKeyJSON             []byte
		customDeriveECDHES           CustomDeriveECDHES
		expectedJwtHeader            string
		expectedEncryptedKey         string
		expectedVI                   string
		expectedCiphertext           string
		expectedAuthTag              string
		cekHex                       string
		seedHex                      string
		ivHex                        string
		encDataFromSpec              string // this is the value in the spec which we will decrypt from
		expectedEncryptedKeyFromSpec string // this is the value from the spec that cannot be generated as we don't know the original random seed
		expectedAuthTagFromSpec      string
	}{
		{
			name:                         "Example 1: SDK Encryption of Device Information and DS Decryption—RSA-based Using RSA-OAEP-256 and A128CBC-HS256 (Page 8)",
			keyAlg:                       RSA_OAEP_256,
			encAlg:                       A128CBC_HS256,
			dsPrivateKeyJSON:             dsRSAPrivateKeyJSON,
			expectedJwtHeader:            `eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0`,
			expectedEncryptedKey:         `WfoH_bEiicOO1j66L5swJSX1x_U_bUO6gjBdkqOC99nCBQ64JRfqDUKp4FgUyOrmY8dBZloVH_F-63G6m3GJs-zZJOPMR_Rxprg-lS7IsTiUAFZekCe4jLngdAcojpQRQvuhemTIqaI9MxQry1L78N9g9_soJyu4TqUbvYzI1KhkCvU6qD0s_gkLSFsQ226tN8OKQY8azSH3MbDxhBaMszZb6bBwxHq2t-2tcl-ZfhKiRQESJLou5SLXAphQGV-6BDoeWPnlUxVoMR0JiCrxJyKetudpZYuoBV8IHrkQqk0GD1jW9VXnQlOu4ADf_nIGWq2MsbvB61r-Oei-pZ7u7A`,
			expectedVI:                   `w4Xg7V7mMrOLvcDCzRvKMw`,
			expectedCiphertext:           `M6PNj79NF-ZW-_Kz-fhjMohqVlUUcwHvZdK4CwKq5mCuY1FwkkHpUPKUbMpf6K4dVeCpgxaFnS6EGesJ7ob1LOeX0n_vU1Uv6xzoTB4yIYYBXynfNMMBz7I9DBuSlhNpCDwjVuJ4HVnuceGAp2ZVfW5J8FrnBeqkhk_ncrF1Eu8P81O7YmB7CH08V3lDpURuXZbTW7apveszjs4F4ZECVyPAwwx7aYfQcudSDHN2-2G8kQDYnZFPNOxtoBSZUTAx43pGqtkFrVEdBkuRavqXR_PvqMHP32U16LnqcW0lBO2h2JI_RgvAH7tUV42KCW4AmMsMWGWs8nWWB0XOE9CZog`,
			expectedAuthTag:              `GBbljhWb1NSVl5C2MixJnQ`,
			cekHex:                       "99831FB208244C09B44DBBED945876872A179DB1332508CCC6680B37777CC570",
			seedHex:                      "0000000000000000000000000000000000000000000000000000000000000000",
			ivHex:                        "C385E0ED5EE632B38BBDC0C2CD1BCA33",
			encDataFromSpec:              `eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.Cpl8tM5eQFNp1QrXy5cGsSHKEpN87xf6hixToV0jLCK5_DzUvpk9EoKBQh8wj6DEcNUjFvgQHb8HapFnvkjU94tdON9Y11fijxXqPYWcYb0y5P8exdYxlnKWBCwY-UY1MgRGnVq7gy4SLaRVvjLO13tkrLd5R-jlMCvyBpHFQVnbcKalfIYM1xoUhkQwDP2Ro80HMxi6VzAsL2QiiqPfGtMCKyvurPBVqGxUaplV0dblcGrVwL4kq9kJup7sEIgTxrj1Rv4LdpIvwJLhvYuCsLOmWO-usSCeZVhM3C-Uv3gwuDmClNsTvzBLBpWnQ5A-K9yDd4wbpL7jXmQe54nFTA.w4Xg7V7mMrOLvcDCzRvKMw.M6PNj79NF-ZW-_Kz-fhjMohqVlUUcwHvZdK4CwKq5mCuY1FwkkHpUPKUbMpf6K4dVeCpgxaFnS6EGesJ7ob1LOeX0n_vU1Uv6xzoTB4yIYYBXynfNMMBz7I9DBuSlhNpCDwjVuJ4HVnuceGAp2ZVfW5J8FrnBeqkhk_ncrF1Eu8P81O7YmB7CH08V3lDpURuXZbTW7apveszjs4F4ZECVyPAwwx7aYfQcudSDHN2-2G8kQDYnZFPNOxtoBSZUTAx43pGqtkFrVEdBkuRavqXR_PvqMHP32U16LnqcW0lBO2h2JI_RgvAH7tUV42KCW4AmMsMWGWs8nWWB0XOE9CZog.GBbljhWb1NSVl5C2MixJnQ`,
			expectedEncryptedKeyFromSpec: `Cpl8tM5eQFNp1QrXy5cGsSHKEpN87xf6hixToV0jLCK5_DzUvpk9EoKBQh8wj6DEcNUjFvgQHb8HapFnvkjU94tdON9Y11fijxXqPYWcYb0y5P8exdYxlnKWBCwY-UY1MgRGnVq7gy4SLaRVvjLO13tkrLd5R-jlMCvyBpHFQVnbcKalfIYM1xoUhkQwDP2Ro80HMxi6VzAsL2QiiqPfGtMCKyvurPBVqGxUaplV0dblcGrVwL4kq9kJup7sEIgTxrj1Rv4LdpIvwJLhvYuCsLOmWO-usSCeZVhM3C-Uv3gwuDmClNsTvzBLBpWnQ5A-K9yDd4wbpL7jXmQe54nFTA`,
			expectedAuthTagFromSpec:      `GBbljhWb1NSVl5C2MixJnQ`,
		},
		{
			name:                         "Example 2: SDK Encryption of Device Information and DS Decryption—RSA-based Using RSA-OAEP-256 and A128GCM (Page 14)",
			keyAlg:                       RSA_OAEP_256,
			encAlg:                       A128GCM,
			dsPrivateKeyJSON:             dsRSAPrivateKeyJSON,
			expectedJwtHeader:            `eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0`,
			expectedEncryptedKey:         `nbrFqROsPr9kYJVxCZpVCH2Y-3majg0-6XnO1hRE-xnvo4-SHeCYF6ufsh-m3pJGxyn_ntoTUl5nwDt6mIi2fYi6_y45fRilkdWgvwLfNAwd2Ucsxh2PRy3KsoXTM1Y0MWTHab_VkfxXYZDj7OoAzqMv-e0AWQ2zZQkvv4ZH3EvkORydaLy7rEpA6tR42aqXgYV0OUyxQm5XgWMc_TLBerV2D3P_OOp5gitk2cvdt7jnx9slzxbca6pOo14uIpuQ9PEp_xLZQMH5MPy6yWc4hzbnD_pTvGpCu06qsiyef35egRwv6dUvJKaEvWCAEItjC0R0hrhjtWHhXhjwycLzEA`,
			expectedVI:                   `rXVNt9JLuDWICZVd`,
			expectedCiphertext:           `oHcea2DjRxZpd1JU5nWrwRipcetrH4EipWUZeP6AvPIk5y7uIsWWGyjWDebbdH9oNNwte7YBJPsWmZ83jRmsFYlfVo1JgI51VMhfQj7XZ2LlGDD-sT99kxVAERfZ2a1-oDDOKVRUroZGfVLSfhbF7OqO82R-Sj7DatCjjhJK3uh0fRKUa6EA6bOmvtP_qjTZ6CWA337na6QeKEOJueul5oLlP0JmNQwC_MuMTvqdO9O4yJM75Wa9k3yeWzp_m0g46oxyblTX97y7UzoKEfLrkBFcjqp8VGH_FylaICUhDiUYIP0URfBiOVo16-ARr7iKfaxMNtShi6KvIiv2`,
			expectedAuthTag:              `AgzuAps_GN0gbLx1scZmqw`,
			cekHex:                       "99831FB208244C09B44DBBED94587687",
			seedHex:                      "0000000000000000000000000000000000000000000000000000000000000000",
			ivHex:                        "AD754DB7D24BB8358809955D",
			encDataFromSpec:              `eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0.lSfh8dkYKN7xB3_k6sqQDW5ovrXFwHbLK6Wm3tzvyuz4nu_M6HM_L46_6bC8_5LXzftYw1do73YRbry4PxaC_WOIaFFm4r5Hqjej-F8RKndc4ebnqDbentirCfPvfTnXjVGzN9Pm-JAp4vCnLqII-mu6mLgpNnZxlN8XsWLhmyjtb-0ux2AdaH-ttu9nK9bF0AIkEjWF5l6HALsYngwEFt4D1VfxMOMyX-65niUZ2fOO6qS93PR78I9FT1v4tTogXhOx9oaPN2bKCFjoOO692G3eIxmZO77xX6ar2U3VVFsOZUKlCzJsyxp9jPbzn24S4QDtBSnzhV02ZniN5cnZoA.rXVNt9JLuDWICZVd.oHcea2DjRxZpd1JU5nWrwRipcetrH4EipWUZeP6AvPIk5y7uIsWWGyjWDebbdH9oNNwte7YBJPsWmZ83jRmsFYlfVo1JgI51VMhfQj7XZ2LlGDD-sT99kxVAERfZ2a1-oDDOKVRUroZGfVLSfhbF7OqO82R-Sj7DatCjjhJK3uh0fRKUa6EA6bOmvtP_qjTZ6CWA337na6QeKEOJueul5oLlP0JmNQwC_MuMTvqdO9O4yJM75Wa9k3yeWzp_m0g46oxyblTX97y7UzoKEfLrkBFcjqp8VGH_FylaICUhDiUYIP0URfBiOVo16-ARr7iKfaxMNtShi6KvIiv2.AgzuAps_GN0gbLx1scZmqw`,
			expectedEncryptedKeyFromSpec: `lSfh8dkYKN7xB3_k6sqQDW5ovrXFwHbLK6Wm3tzvyuz4nu_M6HM_L46_6bC8_5LXzftYw1do73YRbry4PxaC_WOIaFFm4r5Hqjej-F8RKndc4ebnqDbentirCfPvfTnXjVGzN9Pm-JAp4vCnLqII-mu6mLgpNnZxlN8XsWLhmyjtb-0ux2AdaH-ttu9nK9bF0AIkEjWF5l6HALsYngwEFt4D1VfxMOMyX-65niUZ2fOO6qS93PR78I9FT1v4tTogXhOx9oaPN2bKCFjoOO692G3eIxmZO77xX6ar2U3VVFsOZUKlCzJsyxp9jPbzn24S4QDtBSnzhV02ZniN5cnZoA`,
			expectedAuthTagFromSpec:      `AgzuAps_GN0gbLx1scZmqw`,
		},
		{
			name:                         "Example 3: SDK Encryption of Device Information and DS Decryption—EC-based Using ECDH-ES and A128CBC-HS256 (Page 20)",
			keyAlg:                       ECDH_ES,
			encAlg:                       A128CBC_HS256,
			dsPrivateKeyJSON:             dsECPrivateKeyJSON,
			customDeriveECDHES:           createCustomDeriveECDHES(testDirectoryServerID),
			expectedJwtHeader:            `eyJhbGciOiJFQ0RILUVTIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiQzFQTDQyaTZrbU5rTTYxYXVwRUFnTEo0Z0YxWlJ6Y1Y3bHFvMVRHMG1MNCIsInkiOiJjTlRvV0xTZGNGUUtHLS1QR1ZFVVFySUhQOHc2VGNSeWowcHlGeDQtWk1jIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ`,
			expectedEncryptedKey:         ``,
			expectedVI:                   `3ibBWZove6uy5yIjua0yOQ`,
			expectedCiphertext:           `bNuX3UlZY5psfpG6D_bZhmVhQb5RTlwF6jfGX0cPCkNtaJBBoLg6lOA-yduTRDkMEIX1Qew-1vk8K-1HIx2cWfjbWhB0OwNpWk8HTTeRxRDW7ggQg7VNN1WJUAAzjXT13kwJ1Ik0Kj8JxwoQVPS5rX9wOxujsdgOKnadaF3JxR5pUzraNzmvohvql6OL-kERszQzSvza9cWyZPbFXXFWkW2YqHxYp-Oacc65B-D2xxoKUnTzzKGGfTldtTvHbLqXVGu2xnIqDKclKInAZDNO-7yVhuFM2stnSX0X7MzEV_RpI_fqVLbxXQOICrDfkkbnRZT_LcbO4dLTdY_hlnaBeQ`,
			expectedAuthTag:              `-YsNuOi1Ogq129g6Xvi-cw`,
			cekHex:                       "00000000000000008B29FEF886E405E3683EEF1C376E392FAA4E416B769531FC5740ECF768D0995F",
			seedHex:                      "",
			ivHex:                        "DE26C1599A2F7BABB2E72223B9AD3239",
			encDataFromSpec:              `eyJhbGciOiJFQ0RILUVTIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiQzFQTDQyaTZrbU5rTTYxYXVwRUFnTEo0Z0YxWlJ6Y1Y3bHFvMVRHMG1MNCIsInkiOiJjTlRvV0xTZGNGUUtHLS1QR1ZFVVFySUhQOHc2VGNSeWowcHlGeDQtWk1jIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ..3ibBWZove6uy5yIjua0yOQ.bNuX3UlZY5psfpG6D_bZhmVhQb5RTlwF6jfGX0cPCkNtaJBBoLg6lOA-yduTRDkMEIX1Qew-1vk8K-1HIx2cWfjbWhB0OwNpWk8HTTeRxRDW7ggQg7VNN1WJUAAzjXT13kwJ1Ik0Kj8JxwoQVPS5rX9wOxujsdgOKnadaF3JxR5pUzraNzmvohvql6OL-kERszQzSvza9cWyZPbFXXFWkW2YqHxYp-Oacc65B-D2xxoKUnTzzKGGfTldtTvHbLqXVGu2xnIqDKclKInAZDNO-7yVhuFM2stnSX0X7MzEV_RpI_fqVLbxXQOICrDfkkbnRZT_LcbO4dLTdY_hlnaBeQ.Zv-neiatArH5fH1c7GtpZQ`,
			expectedEncryptedKeyFromSpec: ``,
			expectedAuthTagFromSpec:      `Zv-neiatArH5fH1c7GtpZQ`,
		},
		{
			name:                         "Example 4: SDK Encryption of Device Information and DS Decryption—EC-based Using ECDH-ES and A128GCM (Page 27)",
			keyAlg:                       ECDH_ES,
			encAlg:                       A128GCM,
			dsPrivateKeyJSON:             dsECPrivateKeyJSON,
			customDeriveECDHES:           createCustomDeriveECDHES(testDirectoryServerID),
			expectedJwtHeader:            `eyJhbGciOiJFQ0RILUVTIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiQzFQTDQyaTZrbU5rTTYxYXVwRUFnTEo0Z0YxWlJ6Y1Y3bHFvMVRHMG1MNCIsInkiOiJjTlRvV0xTZGNGUUtHLS1QR1ZFVVFySUhQOHc2VGNSeWowcHlGeDQtWk1jIn0sImVuYyI6IkExMjhHQ00ifQ`,
			expectedEncryptedKey:         ``,
			expectedVI:                   `rXVNt9JLuDWICZVd`,
			expectedCiphertext:           `gxgBDzPIywAnUx1TgZ_s8e8wVbrCzTDw7NjYZtDND1fafE-9YBimM6SAPnqjPzbkWam6Ddh7x5oEnZhHEdGj7DyW2hU1MpOfPQbsPcJ1yNUrK6P7ugmyFks8gPaRoxcDjrGyJg0i47-Yn6W_-5lvurVqMOc3fg39Z_opYsMTtTnh13zH3T6eKNlELrzgq4s9-RohGpYAo6JtZA_ZFNZ7R6SFp-2JMx9dVghjj_JE167KNKYwFbARdAaPpDt8MD723MBp1134IcJwQFpUabKc3jobxgc4ZCPu380iRhYvriL1DdotZEgUNMqusnRSgTlCuS8Mh1Cju53nJA7s`,
			expectedAuthTag:              `wNFwOFgIgk1NEVnusmXBSA`,
			cekHex:                       "00000000000000008B29FEF886E405E3683EEF1C376E392FAA4E416B769531FC5740ECF768D0995F",
			seedHex:                      "",
			ivHex:                        "AD754DB7D24BB8358809955D",
			encDataFromSpec:              `eyJhbGciOiJFQ0RILUVTIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiQzFQTDQyaTZrbU5rTTYxYXVwRUFnTEo0Z0YxWlJ6Y1Y3bHFvMVRHMG1MNCIsInkiOiJjTlRvV0xTZGNGUUtHLS1QR1ZFVVFySUhQOHc2VGNSeWowcHlGeDQtWk1jIn0sImVuYyI6IkExMjhHQ00ifQ..rXVNt9JLuDWICZVd.gxgBDzPIywAnUx1TgZ_s8e8wVbrCzTDw7NjYZtDND1fafE-9YBimM6SAPnqjPzbkWam6Ddh7x5oEnZhHEdGj7DyW2hU1MpOfPQbsPcJ1yNUrK6P7ugmyFks8gPaRoxcDjrGyJg0i47-Yn6W_-5lvurVqMOc3fg39Z_opYsMTtTnh13zH3T6eKNlELrzgq4s9-RohGpYAo6JtZA_ZFNZ7R6SFp-2JMx9dVghjj_JE167KNKYwFbARdAaPpDt8MD723MBp1134IcJwQFpUabKc3jobxgc4ZCPu380iRhYvriL1DdotZEgUNMqusnRSgTlCuS8Mh1Cju53nJA7s.PDrafjBt_uj3EluqM90h0Q`,
			expectedEncryptedKeyFromSpec: ``,
			expectedAuthTagFromSpec:      `PDrafjBt_uj3EluqM90h0Q`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer resetRandReader()

			// init random values used in encryption process
			cek, err := hex.DecodeString(tt.cekHex)
			require.NoError(t, err)
			seed, err := hex.DecodeString(tt.seedHex)
			require.NoError(t, err)
			iv, err := hex.DecodeString(tt.ivHex)
			require.NoError(t, err)

			// Mock random reader
			buffer := append(cek, seed...)
			buffer = append(buffer, iv...)
			RandReader = bytes.NewReader(buffer)

			var dsPrivateJWK JSONWebKey
			err = dsPrivateJWK.UnmarshalJSON(tt.dsPrivateKeyJSON)
			require.NoError(t, err)
			require.True(t, dsPrivateJWK.Valid())

			rcpt := Recipient{Algorithm: tt.keyAlg, Key: dsPrivateJWK.Public().Key}

			enc, err := NewEncrypter(tt.encAlg, rcpt, &EncrypterOptions{Compression: NONE, customDeriveECDHES: tt.customDeriveECDHES})
			require.NoError(t, err)

			input := []byte(deviceInfoStr)

			// encrypt device data
			obj, err := enc.Encrypt(input)
			require.NoError(t, err)

			encData, err := obj.CompactSerialize()
			require.NoError(t, err)

			parsed, err := ParseEncrypted(encData)
			require.NoError(t, err)

			// split encData to check each field
			parts := strings.Split(encData, ".")

			require.Equal(t, 5, len(parts), "encData has %d parts, it should have 5")

			jwtHeader := parts[0]
			encryptedKey := parts[1]
			initializationVector := parts[2]
			ciphertext := parts[3]
			authTag := parts[4]

			// the order of the tags in the jwtHeader may differ but the content can be the same
			// to test equality to unmarshal both to a map
			jwtHeaderMap := make(map[string]interface{})
			jwtHeaderJSON, err := base64.RawStdEncoding.DecodeString(jwtHeader)
			require.NoError(t, err)
			err = json.Unmarshal(jwtHeaderJSON, &jwtHeaderMap)
			require.NoError(t, err)

			expectedJwtHeaderMap := make(map[string]interface{})
			expectedJwtHeaderJSON, err := base64.RawStdEncoding.DecodeString(tt.expectedJwtHeader)
			require.NoError(t, err)
			err = json.Unmarshal(expectedJwtHeaderJSON, &expectedJwtHeaderMap)
			require.NoError(t, err)

			// check expected values match
			require.Equal(t, expectedJwtHeaderMap, jwtHeaderMap)
			require.Equal(t, tt.expectedVI, initializationVector)
			require.Equal(t, tt.expectedEncryptedKey, encryptedKey)
			require.Equal(t, tt.expectedCiphertext, ciphertext)
			require.Equal(t, tt.expectedAuthTag, authTag)

			var output []byte
			// decrypt device data
			if tt.customDeriveECDHES != nil {
				output, err = parsed.DecryptWithCustomCek(dsPrivateJWK.Key, tt.customDeriveECDHES)
			} else {
				output, err = parsed.Decrypt(dsPrivateJWK.Key)
			}
			require.NoError(t, err)

			// decrypted data should match
			if !bytes.Equal(input, output) {
				t.Errorf("Decrypted output does not match input, got '%s' but wanted '%s'", output, input)
			}

			// Now we do a second decryption test using the encData value published in the spec
			// this is because we don't know the original random seed used on some of the examples
			// so we are unable to reproduce this encData exactly.
			// This check proves that if we are given the encData value we can decrypt it as expected

			expectedOutput := []byte(deviceInfoStr)

			parsed, err = ParseEncrypted(encData)
			require.NoError(t, err)

			// split encData to check each field
			parts = strings.Split(tt.encDataFromSpec, ".")

			require.Equal(t, 5, len(parts), "encData has wrong number of parts")

			jwtHeader = parts[0]
			encryptedKey = parts[1]
			initializationVector = parts[2]
			ciphertext = parts[3]
			authTag = parts[4]

			require.Equal(t, tt.expectedJwtHeader, jwtHeader)
			require.Equal(t, tt.expectedVI, initializationVector)
			require.Equal(t, tt.expectedEncryptedKeyFromSpec, encryptedKey)
			require.Equal(t, tt.expectedCiphertext, ciphertext)
			require.Equal(t, tt.expectedAuthTagFromSpec, authTag)

			if tt.customDeriveECDHES != nil {
				output, err = parsed.DecryptWithCustomCek(dsPrivateJWK.Key, tt.customDeriveECDHES)
			} else {
				output, err = parsed.Decrypt(dsPrivateJWK.Key)
			}
			require.NoError(t, err)

			if !bytes.Equal(expectedOutput, output) {
				t.Errorf("Decrypted output does not match expectedOutput, got '%s' but wanted '%s'", output, expectedOutput)
			}

		})
	}

}

func TestACSSignedContentExamples(t *testing.T) {

	tests := []struct {
		name              string
		sigAlg            SignatureAlgorithm
		encAlg            ContentEncryption
		certPbACS         string // this is the cert for the ACS signed by the DS CA that contains the public key for decryption
		dsRootCert        string
		acsPrivateKeyJSON []byte // this is the private key that the ACS used to sign the acsSignedContent
		expectedJwtHeader string
		expectedPayload   string
		expectedSignature string
		saltHex           string
		decryptRandHex    string
	}{
		{
			name:              "Example 5: ACS Signed Content and Validation by SDK—RSA-based Using PS256 (Page 33)",
			sigAlg:            PS256,
			certPbACS:         acsDsRsaCertPEM,
			dsRootCert:        sdkDsRootCertPEM,
			acsPrivateKeyJSON: acsRSAPrivateKeyJSON,
			expectedJwtHeader: `eyJhbGciOiJQUzI1NiIsIng1YyI6WyJNSUlEZVRDQ0FtR2dBd0lCQWdJUWJTNEM0QlNpZzd1dUo1dURwZVQ0V0RBTkJna3Foa2lHOXcwQkFRc0ZBREJITVJNd0VRWUtDWkltaVpQeUxHUUJHUllEWTI5dE1SY3dGUVlLQ1pJbWlaUHlMR1FCR1JZSFpYaGhiWEJzWlRFWE1CVUdBMVVFQXd3T1VsTkJJRVY0WVcxd2JHVWdSRk13SGhjTk1UY3hNVEl4TVRFMU5EQXlXaGNOTWpjeE1qTXhNVE16TURBd1dqQklNUk13RVFZS0NaSW1pWlB5TEdRQkdSWURZMjl0TVJjd0ZRWUtDWkltaVpQeUxHUUJHUllIWlhoaGJYQnNaVEVZTUJZR0ExVUVBd3dQVWxOQklFVjRZVzF3YkdVZ1FVTlRNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQWtOclBJQkRYTVU2ZmN5djVpK1FIUUFRK0s4Z3NDM0hKYjdGWWhZYXc4aFhiTkphK3Q4cTBsREt3TFpnUVhZVitmZld4WEp2NUdHcmxaRTRHVTUybGZNRWVnVER6WVRyUlEzdGVwZ0tGak1HZzZJeTZma2wxWk5zeDJnRW9uc25sU2hmekE5R0p3UlRtdEtQYmsxcytod3gxSVU1QVQrQUllbE5xQmdjRjJ2RTVXMjUvU0dHQm9hUk9WZFVZeHFFVERnZ00xejVjS1Y0WmpEWjgrbGg0b1ZCMDdia2FjNkxRZEhwSlVVeVNIL0VyMjBEWHgzMEt5aTk3UGNpWEtUUytRS1hubW04aXZ5UkNtdXgyMlpvUFVpbmQyQktDNU9pRzRNd0FMaGFMMloyazhDc1JkZnkrN2RnN3o0MVJwNkQwWmVFdnRhVXA0Ylg0YUtyYUw0clRmd0lEQVFBQm8yQXdYakFNQmdOVkhSTUJBZjhFQWpBQU1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBZEJnTlZIUTRFRmdRVWt0d2Y2WnBUQ3hqWUt3L0JMVzZQZWlOWDRzd3dId1lEVlIwakJCZ3dGb0FVdzRNQ25id0Q2bTJ3cG5vUTJzTkQ4R3J5UE40d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFHdU5IeHYvQlI2ajdsQ1B5c20xdWhyYmpCT3FkcmhKTVIvSWQ0ZEIyR3RkRVNjbDNpckdQbVh5UTJTbmNUV2hOZnNnc0tEWldwNUJrNytPdG50eTBlTlVNazNoWkVxZ1lqeGh6YXUwNDhYSGJzZkd2b0phTUdaWk5Ud1V2VFV6Mmhra2hncHg5eVFBS0lBMkx6RktjZ1loZWxQdTRHVzVydEV1eHUzSVM2V1l5M0QxR3RGM25hRVdralVyYThoUU9oT2wyUytDWUhtUmQ2bEdrWHlrVkRhak1nZDJBSkZ6WGRLTHhUdDBPWXJXREdsVVN6R0FDUkJDZDV4YlJtQVRJbGR0Y2NhR3FETjFjTld2MEkvYlBOOEVwS1M2QjBXYVpjUGFzSXRLV3BEQzg1SncxR3JEeGRod29LSG94dFNHK29kaVR3QjV6TGJybjJPc1JFNWJWN0U9Il19`,
			// Note expectedPayload value differs from value in spec
			// value in spec is invalid as it uses non-standard quote characters and trailing commas which creates invalid JSON
			expectedPayload:   `eyJhY3NFcGhlbVB1YktleSI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Im1QVUtUX2JBV0dISWhnMFRwampxVnNQMXJYV1F1X3Z3Vk9ISHROa2RZb0EiLCJ5IjoiOEJRQXNJbUdlQVM0NmZ5V3c1TWhZZkdUVDBJakJwRncyU1MzNER2NElycyJ9LCJzZGtFcGhlbVB1YktleSI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlplMmxvU1Yzd3Jyb0tVTl80emh3R2hDcW8zWGh1MXRkNFFqZVE1d0lWUjAiLCJ5IjoiSGxMdGRYQVJZX2Y1NUEzZm56UWJQY202aGdyMzRNcDhwLW51elFDRTBadyJ9LCJhY3NVUkwiOiJodHRwOi8vYWNzc2VydmVyLmRvbWFpbm5hbWUuY29tIn0`,
			expectedSignature: `gZKap_1TNhW0ptVQI3Hj5Qbz-1KKwbRW0RC0hOQcbVxtRsAj2kj2Au-aj7Y1yoCB4M0w0KpjbnOKLDSc19btArmxfuIZeTA2nlVtlHe0OqCwh7vPaoyKcBqCP2veq89z8HgdYudwmvVixV0ASm5F_LVaSvhaYMtDSnRLcZmriNDlaHqyyvr1rKUz0opvpknaBalhzX33lloc9-ONKYzL-LDm53wPzdwmfm5y_8B0NE-6y4Hj-CQxYMqi6iaAQu26ucnTBBaqUgoQ2EhkjmffKUug0coiCC5DYkp1E0xOGlEiPuAkMusgdyFRshIHw8EIJcAtyw9kR0zZdlvCeS3dTw`,
			saltHex:           "0000000000000000000000000000000000000000000000000000000000000001",
			decryptRandHex:    "00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000A",
		},
		{
			name:              "Example 6: ACS Signed Content and Validation by SDK—EC-based Using ES256 (Page 48)",
			sigAlg:            ES256,
			certPbACS:         acsDsEcCertPEM,
			dsRootCert:        sdkDsRootCertPEM,
			acsPrivateKeyJSON: acsECPrivateKeyJSON,
			expectedJwtHeader: `eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDclRDQ0FaV2dBd0lCQWdJUWJTNEM0QlNpZzd1dUo1dURwZVQ0V1RBTkJna3Foa2lHOXcwQkFRc0ZBREJITVJNd0VRWUtDWkltaVpQeUxHUUJHUllEWTI5dE1SY3dGUVlLQ1pJbWlaUHlMR1FCR1JZSFpYaGhiWEJzWlRFWE1CVUdBMVVFQXd3T1VsTkJJRVY0WVcxd2JHVWdSRk13SGhjTk1UY3hNVEl4TVRVME16STNXaGNOTWpjeE1qTXhNVE16TURBd1dqQkhNUk13RVFZS0NaSW1pWlB5TEdRQkdSWURZMjl0TVJjd0ZRWUtDWkltaVpQeUxHUUJHUllIWlhoaGJYQnNaVEVYTUJVR0ExVUVBd3dPUlVNZ1JYaGhiWEJzWlNCQlExTXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBVGZvZml3YzZBaXUxWWc1dkc5ZUtYSGVEQ1ZoOWgzVk1xTjIveUoxQ1dHVWlwOEJqOHErZXJPbzc0dHQ2akVUTXpBYVRwekxaNW9HRFpjZVpmR21NN2RvMkF3WGpBTUJnTlZIUk1CQWY4RUFqQUFNQTRHQTFVZER3RUIvd1FFQXdJSGdEQWRCZ05WSFE0RUZnUVUwQVd0REhSL3ZsUXJSQXo0YUtnSkJsbkZqRXN3SHdZRFZSMGpCQmd3Rm9BVXc0TUNuYndENm0yd3Bub1Eyc05EOEdyeVBONHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRXFsRVJld1VDZUV0dEFrQzBGMTZIamp4ZnYxV2E4bmFEbWFSTDk5UTAvcXFVTjh3MHF3cEFQRjd3bjJhZkxmYUdkKzV1WkViMVROWXdWOUF3OUwvczNCY1NURVJJbDZPRVduK3g3Y3RPbUh5MnZ2N21pdGFVcmlsZUdvZGVubS9mYURkeTVWZ0tZaitLc01WTTJzTlZhZWtYK1Qwc3dBQ1g5QjkwdW5aeGE2MjU2dDJPSjJRVjV6dTNzWU8xTjBqOXY3K3lGK0ZneDAxNE5ydzcvWHQ4SUxHRjU4TnhiUWhraGtmV1NmSHRhRTVtb0JBYldSdUZURmJrQmY0NVNLZTBVTWlVNUxhYzl4STBPN1hDRCt6TkI1bXdzNE5PMkFZdnl4SHE5WCthNjRJaFhjbFhuZ1BRTXJVcU1vTFdJMTY2Z1JKU3ZRRVdzSUxJVXR4MndzaVlzPSJdfQ`,
			// Note expectedPayload value differs from value in spec
			// value in spec is invalid as it uses trailing commas which creates invalid JSON
			expectedPayload:   `eyJhY3NFcGhlbVB1YktleSI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Im1QVUtUX2JBV0dISWhnMFRwampxVnNQMXJYV1F1X3Z3Vk9ISHROa2RZb0EiLCJ5IjoiOEJRQXNJbUdlQVM0NmZ5V3c1TWhZZkdUVDBJakJwRncyU1MzNER2NElycyJ9LCJzZGtFcGhlbVB1YktleSI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlplMmxvU1Yzd3Jyb0tVTl80emh3R2hDcW8zWGh1MXRkNFFqZVE1d0lWUjAiLCJ5IjoiSGxMdGRYQVJZX2Y1NUEzZm56UWJQY202aGdyMzRNcDhwLW51elFDRTBadyJ9LCJhY3NVUkwiOiJodHRwOi8vYWNzc2VydmVyLmRvbWFpbm5hbWUuY29tIn0`,
			expectedSignature: `tqYNdHiSULdehmGBZw-xP2NHL-1ouSKiA5TQvucZEOUVLyVHh9VfJJTnyasbIvNY7TI0dvFjpasHZ-BwK7CDMQ`,
			saltHex:           "0000000000000000000000000000000000000000000000000000000000000001",
			decryptRandHex:    "00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000A",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var acsPrivateJWK JSONWebKey
			err := acsPrivateJWK.UnmarshalJSON(tt.acsPrivateKeyJSON)
			require.NoError(t, err)
			require.True(t, acsPrivateJWK.Valid())

			// setup randReader
			defer resetRandReader()

			// init random values used in signing process
			salt, err := hex.DecodeString(tt.saltHex)
			require.NoError(t, err)
			decryptRand, err := hex.DecodeString(tt.decryptRandHex)
			require.NoError(t, err)

			// Mock random reader
			buffer := append(salt, decryptRand...)
			RandReader = bytes.NewReader(buffer)

			// parse DS cert to attach to x5c header
			block, _ := pem.Decode([]byte(tt.certPbACS))
			if block == nil {
				t.Fatalf("failed to parse certificate PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)

			fmt.Printf("TEMP: cert pubkey: %#v\n", cert.PublicKey)

			signerOpts := &SignerOptions{
				ExtraHeaders: map[HeaderKey]interface{}{
					"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
				},
			}

			signer, err := NewSigner(SigningKey{Algorithm: tt.sigAlg, Key: acsPrivateJWK.Key}, signerOpts)
			require.NoError(t, err)

			input := []byte(acsContentStr)
			obj, err := signer.Sign(input)
			require.NoError(t, err)

			acsSignedContent, err := obj.CompactSerialize()
			require.NoError(t, err)

			// split acsSignedContent to check each field
			parts := strings.Split(acsSignedContent, ".")

			require.Equal(t, 3, len(parts), "acsSignedContent has %d parts, it should have 3")

			jwtHeader := parts[0]
			payload := parts[1]
			signature := parts[2]

			// check expected values match
			require.Equal(t, tt.expectedJwtHeader, jwtHeader)
			require.Equal(t, tt.expectedPayload, payload)
			require.Equal(t, tt.expectedSignature, signature)

			// parse DS cert known to the SDK
			block, _ = pem.Decode([]byte(tt.dsRootCert))
			if block == nil {
				t.Fatalf("failed to parse certificate PEM")
			}

			sigs, err := ParseSigned(acsSignedContent)
			require.NoError(t, err)

			require.Equal(t, 1, len(sigs.Signatures))

			sdkDSRootCert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)

			roots := x509.NewCertPool()
			roots.AddCert(sdkDSRootCert)

			verifyOpts := x509.VerifyOptions{
				//DNSName: "RSA Example DS",
				Roots: roots,
			}

			certChain, err := sigs.Signatures[0].Protected.Certificates(verifyOpts)
			require.NoError(t, err)
			require.NotNil(t, certChain)

			var acsPubKey interface{}
			for _, certs := range certChain {
				for _, cert := range certs {
					if !cert.IsCA {
						acsPubKey = cert.PublicKey
					}
				}
			}

			// verify with public key in header
			verifiedContent, err := obj.Verify(acsPubKey)
			require.NoError(t, err)
			require.Equal(t, acsContentStr, string(verifiedContent))

			// x5cArray, ok := sigs.Signatures[0].Protected.ExtraHeaders["x5c"]
			// require.True(t, ok)

			// //require.Equal(t, 1, len(sigs.Signatures[0].Protected))

			// // must have one cert
			// base64x5c := x5cArray.([]string)
			// require.Equal(t, 1, len(base64x5c))

			// // decode x5c
			// headerCertBytes, err := base64.StdEncoding.DecodeString(base64x5c[0])
			// require.NoError(t, err)

			// headerCert, err := x509.ParseCertificate(headerCertBytes)
			// require.NoError(t, err)

			// validate ACS public cert against SDK DS cert
			// TODO

		})
	}

}

// ACS Diffie-Hellman and Session Key Derivation—EC-based Using ECDH-ES (Page 59)
func TestExample7(t *testing.T) {
	// TODO
}

// SDK Diffie-Hellman and Session Key Derivation—EC-based Using ECDH-ES (Page 61)
func TestExample8(t *testing.T) {
	// TODO
}

// SDK Encryption of CReq and ACS Decryption—Using A128CBC-HS256 (Page 63)
func TestExample9(t *testing.T) {
	// TODO
}

// SDK Encryption of CReq and ACS Decryption—Using A128GCM (Page 68)
func TestExample10(t *testing.T) {
	// TODO
}

// ACS Encryption of CRes and SDK Decryption—Using A128CBC-HS256 (Page 71)
func TestExample11(t *testing.T) {
	// TODO
}

// ACS Encryption of CRes and SDK Decryption—Using A128GCM (Page 82)
func TestExample12(t *testing.T) {
	// TODO
}
