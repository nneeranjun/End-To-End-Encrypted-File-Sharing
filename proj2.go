package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"
	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes: 
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func getHKDFKey(password []byte, username []byte) (hkdfKey []byte) {
	//MAC key generated for MAC'ing
	hkdfKey = userlib.Argon2Key(password, username, 32)
	return hkdfKey
}

func encryptionHelper(password []byte, username []byte) (macKey []byte, symmKey []byte) {
	//MAC key generated for MAC'ing
	var hkdfKey = userlib.Argon2Key(password, username, 32)
	macKey, _ = userlib.HashKDF(hkdfKey, []byte("mac"))
	macKey = macKey[:16]
	//Symmetric key generated used for symmetric encryption
	symmKey, _ = userlib.HashKDF(hkdfKey, []byte("symmetric key"))
	symmKey = symmKey[:16]
	return macKey, symmKey
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	SecretKeyEnc userlib.PKEDecKey
	DSSignKey userlib.DSSignKey
	AccessTokenMap map[string] AccessToken
	//TODO: Add files and access tokens


	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

//Access Token object with the symmetric key and the unique identifier which shouldn't reveal
//anything about the filename
type AccessToken struct {
	 SymmetricKey[] byte
	 UniqueIdentifier[] byte
	 MacKey[] byte
}

type File struct {
	Contents[][] byte
	//SharingTree SharingTree
}

//Generates a unique access token object for a filename
func (user *User) GenerateAccessToken(filename string) (accessToken AccessToken){
	hkdfKey := getHKDFKey([]byte(user.Username), []byte(user.Password))
	symmKey, _ := userlib.HashKDF(hkdfKey, []byte(filename)) //TODO: this could be repeating for the same filename!
	symmKey = symmKey[:16]
	uI := userlib.RandomBytes(16)
	uI = uI[:16]
	macKey := userlib.RandomBytes(16)
	macKey = macKey[:16]
	accessToken.MacKey = macKey
	accessToken.SymmetricKey = symmKey
	accessToken.UniqueIdentifier = uI
	return accessToken
}

func (userdata *User) getAccessTokenFields(filename string) (fileUniqueID []byte, fileSymmKey []byte, fileMACKey []byte) {
	username := userdata.Username
	password := userdata.Password
	//fetch user data to get accessToken. Create variables for accessToken fields.
	datastoreUser, err := GetUser(username, password)
	if err != nil {
		return
	}
	accessToken := datastoreUser.AccessTokenMap[filename]
	fileUniqueID, fileSymmKey, fileMACKey =  accessToken.UniqueIdentifier, accessToken.SymmetricKey, accessToken.MacKey
	return fileUniqueID, fileSymmKey, fileMACKey
}

func (userdata *User) GetFile(filename string, fileUniqueID []byte) (fileUUID uuid.UUID, unmarshFilePtr *File, err error) {
	var unmarshFile File
	unmarshFilePtr = &unmarshFile
	//use file UUID to get file from Datastore

	fileUUID, fileUUIDErr := uuid.FromBytes(fileUniqueID)
	//println("FILE UUID: ", fileUUID.String())
	//println("FILE UUID LENGTH: ", len(fileUUID))

	if fileUUIDErr != nil {
		println("Error: File UUID byte slice does not have a length of 16!")
	}
	marshFile, fileOk := userlib.DatastoreGet(fileUUID)

	//Error getting file, so return (nil, error)
	if fileOk == false  {
		fileLoadErr := errors.New(strings.ToTitle("Error: Can't load file!"))
		return fileUUID, nil, fileLoadErr
	}

	//unmarshal file's "Contents" field to get encrypted file contents
	unmarshalFileErr := json.Unmarshal(marshFile, unmarshFilePtr)
	// If there is an error with un-marshalling the file, print out an error.
	if unmarshalFileErr != nil {
		println("Error: Can't un-marshall the file")
	}
	return fileUUID, unmarshFilePtr, nil
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing 
// hashes of common passwords downloaded from the internet.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//TODO: This is a toy implementation.
	macKey, symmetricKey := encryptionHelper([]byte(password), []byte(username))

	//Generate public & private keys for public key crypto. RSA Encryption guarantees confidentiality for asymmetric-keys.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()

	//Generate public & private keys for digital signatures. RSA Signatures guarantee integrity + authenticity for asymmetric-keys.
	var vk userlib.DSVerifyKey
	var dssk userlib.DSSignKey
	dssk, vk, _ = userlib.DSKeyGen()

	errorPKE := userlib.KeystoreSet(username + " " + "public key", pk) //storing public key in Keystore
	errorDS := userlib.KeystoreSet(username + " " + "verify key", vk) //storing verify key in Keystore

	//error if username already exists
	if errorPKE != nil {
		return nil, errorPKE
	} else if errorDS != nil {
		return nil, errorDS
	}

	var macUsername, _ = userlib.HMACEval(macKey, []byte(username)) //Hash (MAC) username so that we can use bytesToUUID

	//Storing username, secret key, and signing key in user struct
	userdata.Username = username
	userdata.Password = password
	userdata.DSSignKey = dssk
	userdata.SecretKeyEnc = sk

	// TODO: Make empty File map? For now, assuming we add file map in StoreFile.
	/*userdata.FileMap = make(map[string][]byte)
	userdata.FileNames = ""
	userdata.FileContents = nil*/

	userdata.AccessTokenMap = make(map[string] AccessToken)

	var UUID = bytesToUUID(macUsername)
	//Marshal the userdata struct, so it's JSON encoded.
	var data, _ = json.Marshal(userdata)
	//encrypt user data
	var encryptedData = userlib.SymEnc(symmetricKey, userlib.RandomBytes(16), data)
	//mac user data
	var MAC, _ = userlib.HMACEval(macKey, encryptedData)

	var dataPlusMAC =  append(encryptedData[:], MAC[:]...) //appending MAC to encrypted user struct
	//print(len(x) == len(encryptedData) + len(MAC))
	//println("TOTAL:")
	//println(x)

	userlib.DatastoreSet(UUID, dataPlusMAC)
	//********************************** END OF NEW IMPLEMENTATION *****************************************************************
	return &userdata, nil
}



// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	macKey, symmKey := encryptionHelper([]byte(password), []byte(username))
	var macUsername, _ = userlib.HMACEval(macKey, []byte(username)) //Hash (MAC) username so that we can use bytesToUUID
	var UUID = bytesToUUID(macUsername)
	var datastoreUser, ok = userlib.DatastoreGet(UUID)
	if ok == false {
		return nil, errors.New("Username/Password invalid")
	}
	var ciphertext = datastoreUser[0: len(datastoreUser) - 64]
	var macRec = datastoreUser[len(datastoreUser) - 64: ] //Mac received from Datastore
	var macComp, _ = userlib.HMACEval(macKey, ciphertext) //recompute MAC

	if userlib.HMACEqual(macRec, macComp) == false {
		return nil, errors.New("data corrupted")
	}

	//Data is now verified, can decrypt data
	var decryptedData = userlib.SymDec(symmKey, ciphertext)
	_ = json.Unmarshal(decryptedData, userdataptr)

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename 
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//TODO: This is a toy implementation.
	username := userdata.Username
	password := userdata.Password
	macKey, symmKey := encryptionHelper([]byte(password), []byte(username))
	var macUsername, _ = userlib.HMACEval(macKey, []byte(username)) //Hash (MAC) username so that we can use bytesToUUID
	var UUID = bytesToUUID(macUsername)
	//fetch and decrypt/verify user data. If error, return
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return
	}

	accessToken := userdata.GenerateAccessToken(filename) //generate access token
	userdata.AccessTokenMap[filename] = accessToken //set access token

	//Encrypt and MAC File Contents
	encryptedContents := userlib.SymEnc(accessToken.SymmetricKey, userlib.RandomBytes(16), data)
	MAC, _ := userlib.HMACEval(accessToken.MacKey, encryptedContents)
	fileDataPlusMAC := append(encryptedContents[:], MAC[:]...)

	//Create File
	fileContents := [][]byte{fileDataPlusMAC}
	file := File{Contents: fileContents}

	//TODO: Need to make SharingTree

	marshalledData, _ := json.Marshal(file) //Marshall Data
	fileUUID, _:= uuid.FromBytes(accessToken.UniqueIdentifier) //Generate UUID from unique identifier
	userlib.DatastoreSet(fileUUID, marshalledData) //Push (ui, file) to DataStore

	//Push user data
	data, _ = json.Marshal(userdata)
	//encrypt user data
	var encryptedData = userlib.SymEnc(symmKey, userlib.RandomBytes(16), data)
	//mac user data
	var userMAC, _ = userlib.HMACEval(macKey, encryptedData)

	var dataPlusMAC =  append(encryptedData[:], userMAC[:]...) //appending MAC to encrypted user struct

	userlib.DatastoreSet(UUID, dataPlusMAC)
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	fileUniqueID, fileSymmKey, fileMACKey := userdata.getAccessTokenFields(filename)
	fileUUID, unmarshalFile, fileLoadErr := userdata.GetFile(filename, fileUniqueID)

	//Error with loading file
	if fileLoadErr != nil  {
		return fileLoadErr
	}
	var encMACFileContents = unmarshalFile.Contents
	//encrypt and mac new data
	encData := userlib.SymEnc(fileSymmKey, userlib.RandomBytes(16), data)
	macData, macErr := userlib.HMACEval(fileMACKey, encData)

	//Error MAC'ing data we want to append to file
	if macErr != nil {
		return errors.New(strings.ToTitle("Error: Can't MAC data we want to append!"))
	}

	//combine encData and macData and append to existing file contents
	encMACData := append(encData[:], macData...)
	encMACFileContents = append(encMACFileContents, [][]byte{encMACData}...)

	//update file with newly appended file contents
	unmarshalFile.Contents = encMACFileContents

	//marshal file
	marshalFile, _ := json.Marshal(unmarshalFile) //Marshall Data

	//Store updated file in DataStore
	userlib.DatastoreSet(fileUUID, marshalFile)
	//No error appending new data to file; return nil as error!
	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	fileUniqueID, fileSymmKey, fileMACKey := userdata.getAccessTokenFields(filename)
	_, unmarshalFile, fileLoadErr := userdata.GetFile(filename, fileUniqueID)
	//Error with loading file
	if fileLoadErr != nil  {
		return nil, fileLoadErr
	}
	// Access file contents
	encMACFileContents := unmarshalFile.Contents

	// Set up variables for iteration
	numFiles := len(encMACFileContents)
	var decryptedFile []byte

	for i:= 0; i < numFiles; i++ {
		fileSlice := encMACFileContents[i]
		sliceLen := len(fileSlice)
		encSliceData := fileSlice[:sliceLen-64]
		ogSliceMAC :=  fileSlice[sliceLen-64:]
		// Verify file contents integrity
		println("file mac key length: ", len(fileMACKey))
		newSliceMAC, sliceMACErr := userlib.HMACEval(fileMACKey, encSliceData)
		if sliceMACErr != nil {
			return nil, errors.New(strings.ToTitle("Error: File integrity cannot be verified!"))
		}
		isSameMAC := userlib.HMACEqual(ogSliceMAC, newSliceMAC)
		if !isSameMAC {
			return nil, errors.New(strings.ToTitle("Error: Unauthorized modifications to the file!"))
		}
		// File integrity not compromised, so decrypt file data.
		decSliceData := userlib.SymDec(fileSymmKey, encSliceData)
		decryptedFile = append(decryptedFile, decSliceData...)
	}

	return decryptedFile, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	//fetch most recent user data
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return
	}

	//Generates an access token to be sent to the recipient.
	accessTokenMap := userdata.AccessTokenMap //get access token map
	accessToken := accessTokenMap[filename]
	_, _, fileLoadErr := userdata.GetFile(filename, accessToken.UniqueIdentifier)

	//If the file does not exist or sharing cannot complete due to malicious action, return an empty string and a non-nil error.
	if fileLoadErr != nil  {	//File doesn't exist.
		return "", fileLoadErr
	}

	//get recipient PK and error checking
	recipientPK, recipientPKExists := userlib.KeystoreGet(recipient + " " + "public key")
	if !recipientPKExists {
		println("Recipient PK doesn't exist in the Keystore!")
	}

	//marshal + encrypt access token and error checking
	marshalAT,_ := json.Marshal(accessToken)
	encAT, encATErr := userlib.PKEEnc(recipientPK, marshalAT)
	if encATErr != nil {
		println("Can't encrypt Access Token!")
	}

	//sign encrypted access token and set magic string to the encrypted access token concatenated with the signature
	dsAT, dsATErr := userlib.DSSign(userdata.DSSignKey, encAT)
	if dsATErr != nil {
		println("Can't sign encrypted access token!")
	}
	encSignAT := append(encAT, dsAT...)
	magic_string = string(encSignAT)

	return magic_string, nil

	//TODO: Update sharing tree for both sender and recipient.
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {
	//cast magic string back to byte array and get encrypted access token and its signature
	accessTokenAndSig:= []byte(magic_string)
	println("LENGTH OF ACCESS TOKEN AND SIG: ", len(accessTokenAndSig))
	encAT, sig := accessTokenAndSig[0:len(accessTokenAndSig)-256], accessTokenAndSig[len(accessTokenAndSig)-256:]
	println(len(encAT))
	println(len(sig))
	println()

	//get sender's VK and error checking
	senderVK, senderVKExists := userlib.KeystoreGet(sender + " " + "verify key")
	if !senderVKExists {
		println("Sender's VK doesn't exist in the Keystore!")
	}

	//verify integrity of access token
	verifyErr := userlib.DSVerify(senderVK, encAT, sig)
	if verifyErr != nil {
		return verifyErr
	}

	//Decrypt access token
	decAT, decErr := userlib.PKEDec(userdata.SecretKeyEnc, encAT)
	if decErr != nil {
		println("Can't decrypt access token!")
	}

	//Unmarshal decrypted access token
	var receivedAT AccessToken
	json.Unmarshal(decAT, &receivedAT)

	//Get user + update userstruct's access token map with received access token
	userdata, getUserErr := GetUser(userdata.Username, userdata.Password)
	if getUserErr != nil {
		println("Can't get user")
	}
	userdata.AccessTokenMap[filename] = receivedAT

	//Save userstruct in datastore
	macKey, symmKey := encryptionHelper([]byte(userdata.Password), []byte(userdata.Username))
	var macUsername, _ = userlib.HMACEval(macKey, []byte(userdata.Username)) //Hash (MAC) username so that we can use bytesToUUID
	var UUID = bytesToUUID(macUsername)
	var data, _ = json.Marshal(userdata)
	var encryptedData = userlib.SymEnc(symmKey, userlib.RandomBytes(16), data)
	var MAC, _ = userlib.HMACEval(macKey, encryptedData)
	var dataPlusMAC =  append(encryptedData, MAC...) //appending MAC to encrypted user struct
	userlib.DatastoreSet(UUID, dataPlusMAC)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {




	return
}
