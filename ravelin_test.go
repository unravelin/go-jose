package jose

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

			require.Equal(t, 5, len(parts), "encData has wrong number of parts")

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

// ACS Signed Content and Validation by SDK—RSA-based Using PS256 (Page 33)
func TestExample5(t *testing.T) {
	// TODO
}

// ACS Signed Content and Validation by SDK—EC-based Using ES256 (Page 48)
func TestExample6(t *testing.T) {
	// TODO
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
